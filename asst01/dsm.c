#include <sys/socket.h>
#include <stdint.h>

#include "param.h"
#include "commonlib.h"

int generate_client_nid(int seek)
{
    return seek;
}

int main(int argc, char *argv[])
{
    // parse arguments
    Parameters *parameters = parse_argv(argc, argv);

    if (!parameters)
    {
        exit(EXIT_FAILURE);
    }
    //FILE* fpp;

    const char *server_ip = get_localhost_ip();
    const int server_port = getpid();

    // set socket
    int server_socket_fd;
    if ((server_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
        perror("Server socket cannot create.");
        exit(EXIT_FAILURE);
    }
    set_socket_timeout(server_socket_fd, SOCKET_TIMEOUT);

    // set address
    struct sockaddr_in server_addr;
    init_sockaddr_in(&server_addr, NULL, server_port);

    // bind && listen socket
    if (bind(server_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perrorf("Server cannot bind to %s:%d\n",
                inet_ntoa(server_addr.sin_addr),
                (int)ntohs(server_addr.sin_port));
        exit(EXIT_FAILURE);
    }
    if (listen(server_socket_fd, parameters->host_num) < 0)
    {
        perrorf("Socket cannot listen to %s:%d\n",
                inet_ntoa(server_addr.sin_addr),
                (int)ntohs(server_addr.sin_port));
        exit(EXIT_FAILURE);
    }

    // ssh
    allocator_printf("Forking %d ssh processes to call '%s' on hosts......\n",
                     parameters->host_num,
                     parameters->execute_file);
    if (parameters->log_file != NULL)
    {
        sm_log_init(parameters->log_file);
        LOG_PRINT("Forking %d ssh processes to call '%s' on hosts......\n",
                  parameters->host_num,
                  parameters->execute_file); // write log file
        sm_log_close(parameters->log_file);
    }

    pid_t pid_ssh = getpid();
    unsigned i;
    for (i = 0; i <= parameters->host_num; ++i)
    {
        if (pid_ssh > 0) // make sure child process won't execut in next turn(only execute once)
        {
            if (i < parameters->host_num)
            {
                pid_ssh = fork();
            }

            if (pid_ssh == 0)
            {
                char sshCommand[1024];
                if (parameters->host_names)
                {
                    snprintf(sshCommand,
                             sizeof(sshCommand),
                             "ssh %s %s %s %d %d %d %s",
                             parameters->host_names[i].host_name,
                             parameters->execute_file,
                             server_ip,
                             server_port,
                             parameters->host_num,
                             generate_client_nid(i),
                             (parameters->node_option ? parameters->node_option : ""));
                }
                else
                {
                    snprintf(sshCommand,
                             sizeof(sshCommand),
                             "%s %s %d %d %d %s",
                             parameters->execute_file,
                             "127.0.0.1",
                             server_port,
                             parameters->host_num,
                             generate_client_nid(i),
                             (parameters->node_option ? parameters->node_option : ""));
                }
                system(sshCommand);
                // system("ssh vina00 ~/Desktop/9243/assign1/client server_ip server_port p nodes i");
            }
            else if (pid_ssh > 0)
            {
                if (i < parameters->host_num)
                {
                    // TODO add pid in manager
                    allocator_printf("SSH process pid is %d\n", pid_ssh);

                    if (parameters->log_file != NULL)
                    {
                        sm_log_init(parameters->log_file);
                        LOG_PRINT("In main process: %d, new process is: %d\n", getpid(), pid_ssh); //write log
                        sm_log_close(parameters->log_file);
                    }
                }
                else //i == parameters->host_num
                {
                    /**
                     * to make sure the main process only execute once
                     * AND
                     * to make sure fork() will not be blocked by the socket processing in main process
                     */
                    allocator_printf("main process pid is %d\n", getpid());

                    int client_socket_fds[parameters->host_num];
                    int client_nids[parameters->host_num];

                    struct sockaddr_in client_addr;
                    socklen_t sizeof_sockaddr_in = sizeof(client_addr);

                    unsigned ii = 0;

                    // Accept all the connection from hosts
                    for (ii = 0; ii < parameters->host_num; ++ii)
                    {
                        if ((client_socket_fds[ii] = accept(server_socket_fd, (struct sockaddr *)&client_addr, &sizeof_sockaddr_in)) < 0)
                        {
                            perrorf("Socket#%d cannot accept\n", ii);
                            exit(EXIT_FAILURE);
                        }
                        client_nids[ii] = 0; // will be set by client msg

                        //set client socket nonblock
                        set_fd_nonblock(client_socket_fds[ii]);
                    }

                    unsigned offline_host = 0;
                    int barrier_count = 0;
                    void *aligned_sm_addr = UINTPTR_MAX; //select the minimum as the aligned address
                    while (true)
                    {
                        for (ii = 0; ii < parameters->host_num; ++ii)
                        {
                            if (!client_socket_fds[ii])
                            {
                                ++offline_host;
                                continue;
                            }

                            struct sm_ptr *msg = protocol_read(client_socket_fds[ii]);
                            if (msg) // msg coming in
                            {
                                if (parameters->log_file != NULL)
                                {
                                    sm_log_init(parameters->log_file);
                                    LOG_PRINT("Server: %s\n", msg);
                                    sm_log_close(parameters->log_file);
                                }

                                if (DEBUG)
                                {
                                    allocator_printf("");
                                    sm_ptr_print(msg);
                                    printf("\n");
                                }

                                void **cmd_data = parse_msg(msg);
                                free(msg->ptr);
                                free(msg);

                                if (!cmd_data)
                                {
                                    allocator_printf("Invalid message received.\n");
                                    exit(EXIT_FAILURE);
                                }
                                char *cmd = (char *)cmd_data[0];
                                struct sm_ptr *data = (struct sm_ptr *)cmd_data[1];

                                if (!strcmp(CLIENT_CMD_REGISTER, cmd)) // save the client register nid; send confirm msg
                                {
                                    memcpy(&(client_nids[ii]), data->ptr, sizeof(client_nids[ii]));
                                    void *sm_addr;
                                    memcpy(&sm_addr, data->ptr + sizeof(client_nids[ii]), sizeof(sm_addr));
                                    if (DEBUG)
                                    {
                                        allocator_printf("a native sm_address is %p\n", sm_addr);
                                    }
                                    if (sm_addr < aligned_sm_addr)
                                    {
                                        aligned_sm_addr = sm_addr;
                                    }
                                    if (DEBUG)
                                    {
                                        allocator_printf("current aligned sm_address is %p\n", aligned_sm_addr);
                                    }
                                    if (ii == parameters->host_num - 1) //all nodes have registered
                                    {
                                        free(data->ptr);
                                        free(data);

                                        data = malloc(sizeof(struct sm_ptr));
                                        data->size = sizeof(void *);
                                        char *data_ptr = malloc(data->size);
                                        memcpy(data_ptr, &aligned_sm_addr, sizeof(aligned_sm_addr));
                                        data->ptr = data_ptr; // data:{void*}
                                        char *confirm_cmd = generate_confirm_cmd(CLIENT_CMD_REGISTER);
                                        msg = generate_msg(confirm_cmd, data);
                                        free(confirm_cmd);
                                        unsigned iii;
                                        for (iii = 0; iii < parameters->host_num; ++iii)
                                        {
                                            protocol_write(client_socket_fds[iii], msg);
                                        }
                                        free(msg->ptr);
                                        free(msg);
                                    }
                                }
                                else if (!strcmp(CLIENT_CMD_ALIGN, cmd)) // save the client register nid; send confirm msg
                                {
                                    void *sm_addr;
                                    memcpy(&sm_addr, data->ptr, sizeof(sm_addr));
                                    if (DEBUG)
                                    {
                                        allocator_printf("a aligned sm_address from node is %p\n", sm_addr);
                                    }
                                    if (ii == 0)
                                    {
                                        aligned_sm_addr = sm_addr;
                                    }

                                    free(data->ptr);
                                    free(data);

                                    data = malloc(sizeof(struct sm_ptr));
                                    data->size = sizeof(bool);
                                    char *data_ptr = malloc(data->size);
                                    bool is_align_success;

                                    if (aligned_sm_addr != sm_addr || ii == parameters->host_num - 1)
                                    {
                                        if (ii == parameters->host_num - 1)
                                        {
                                            is_align_success = true;
                                        }
                                        if (aligned_sm_addr != sm_addr)
                                        {
                                            is_align_success = false;
                                        }

                                        memcpy(data_ptr, &is_align_success, sizeof(is_align_success));
                                        data->ptr = data_ptr; // data:{void*}
                                        char *confirm_cmd = generate_confirm_cmd(CLIENT_CMD_ALIGN);
                                        msg = generate_msg(confirm_cmd, data);
                                        free(confirm_cmd);
                                        unsigned iii;
                                        for (iii = 0; iii < parameters->host_num; ++iii)
                                        {
                                            protocol_write(client_socket_fds[iii], msg);
                                        }

                                        free(msg->ptr);
                                        free(msg);
                                    }
                                }
                                else if (!strcmp(CLIENT_CMD_EXIT, cmd)) // receive sm_node_exit() from nid, then server wait for all host send this
                                {
                                    // set this offline
                                    close(client_socket_fds[ii]);
                                    client_socket_fds[ii] = 0;
                                }
                                else if (!strcmp(CLIENT_CMD_BARRIER, cmd))
                                {
                                    ++barrier_count;
                                }
                                free(cmd);
                                free(data->ptr);
                                free(data);
                                free(cmd_data);
                            }
                            else // connection break
                            {
                                // printf("Socket seems disconnect\n");
                                // set this offline
                                close(client_socket_fds[ii]);
                                client_socket_fds[ii] = 0;
                                // notify the other client to exit();

                                msg = generate_msg(SERVER_CMD_EXIT_CLIENTS, NULL);
                                for (ii = 0; ii < parameters->host_num; ++ii)
                                {
                                    if (client_socket_fds[ii])
                                    {
                                        protocol_write(client_socket_fds[ii], msg);
                                        close(client_socket_fds[ii]);
                                    }
                                }
                                free(msg->ptr);
                                free(msg);
                                if (parameters->log_file != NULL)
                                {
                                    sm_log_close(parameters->log_file); //close log
                                }
                                sm_log_close(parameters->log_file);

                                return;
                            }
                        }

                        if (offline_host >= parameters->host_num) // all the host offline
                        {

                            if (parameters->log_file != NULL)
                            {
                                sm_log_close(parameters->log_file); //close log
                            }
                            return;
                        }

                        if (parameters->host_num == barrier_count)
                        {
                            unsigned jj;

                            char *confirm_cmd = generate_confirm_cmd(CLIENT_CMD_BARRIER);
                            struct sm_ptr *msg = generate_msg(confirm_cmd, NULL);
                            free(confirm_cmd);

                            for (jj = 0; jj < barrier_count; ++jj)
                            {
                                protocol_write(client_socket_fds[jj], msg);
                            }
                            barrier_count = 0;
                            free(msg->ptr);
                            free(msg);
                        }
                    }
                }
            }
            else
            {
                perror("Cannot fork ssh process.\n");
                exit(EXIT_FAILURE);
            }
        }
    }
}
