#include "param.h"
#include "commonlib.h"

int generate_client_nid(int seek)
{
    return 10000 + seek;
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
    printf("Forking %d ssh processes to call '%s' on hosts......\n",
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
                    printf("In main process: %d, new process is: %d\n", getpid(), pid_ssh);
                    //sm_log_init(parameters->log_file);

                    if (parameters->log_file != NULL)
                    {
                        sm_log_init(parameters->log_file);
                        LOG_PRINT("In main process: %d, new process is: %d\n", getpid(), pid_ssh); //write log
                        sm_log_close(parameters->log_file);
                    }

                    // TODO add pid in manager
                }
                else //i == parameters->host_num
                {
                    /**
                     * to make sure the main process only execute once
                     * AND
                     * to make sure fork() will not be blocked by the socket processing in main process
                     */
                    // printf("In main process: %d\n", getpid());

                    int client_socket_fds[parameters->host_num];
                    int client_nids[parameters->host_num];

                    struct sockaddr_in client_addr;
                    socklen_t sizeof_sockaddr_in = sizeof(client_addr);

                    unsigned ii = 0;
                    char buf[BUFSIZ];
                    int len;

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
                    while (1)
                    {
                        for (ii = 0; ii < parameters->host_num; ++ii)
                        {
                            if (!client_socket_fds[ii])
                            {
                                ++offline_host;
                                continue;
                            }

                            len = protocol_read(client_socket_fds[ii], buf);
                            if (len > 0) // msg coming in
                            {
                                int nid;
                                char *client_msg, *confirm_client_msg;

                                printf("Server: %s\n", buf);

                                if (parameters->log_file != NULL)
                                {
                                    sm_log_init(parameters->log_file);
                                    LOG_PRINT("Server: %s\n", buf);
                                    sm_log_close(parameters->log_file);
                                }

                                if (!(client_msg = split_client_msg(buf, &nid)))
                                {
                                    printf("Invalid message received.\n");

                                    exit(EXIT_FAILURE);
                                }

                                if (!strcmp(CLIENT_MSG_REGISTER, client_msg)) // save the client register nid; send confirm msg
                                {
                                    client_nids[ii] = nid;
                                    confirm_client_msg = generate_confirm_msg(CLIENT_MSG_REGISTER);
                                    protocol_write(client_socket_fds[ii], confirm_client_msg);
                                }
                                else if (!strcmp(CLIENT_MSG_EXIT, client_msg)) // receive sm_node_exit() from nid, then server wait for all host send this
                                {
                                    // set this offline
                                    close(client_socket_fds[ii]);
                                    client_socket_fds[ii] = 0;
                                }
                                else if (!strcmp(SERVER_MSG_BARRIER, client_msg))
                                {
                                    ++barrier_count;
                                }
                                if (client_msg != confirm_client_msg) // client_msg == confirm_client_msg == NULL will course "free(): invalid next size (fast)"
                                {
                                    free(client_msg);
                                    free(confirm_client_msg);
                                }
                            }
                            else if (len < 0 && check_errno()) //no msg, continue
                            {
                                // sleep(10);
                                // len = snprintf(buf,
                                //                sizeof(buf),
                                //                "Welcome to this shared memory system.");
                                // buf[len] = '\0';
                            }
                            else if (len == 0) // connection break
                            {
                                // printf("Socket seems disconnect\n");
                                // set this offline
                                close(client_socket_fds[ii]);
                                client_socket_fds[ii] = 0;
                                // notify the other client to exit();

                                for (ii = 0; ii < parameters->host_num; ++ii)
                                {
                                    if (client_socket_fds[ii])
                                    {
                                        protocol_write(client_socket_fds[ii], SERVER_MSG_EXIT_CLIENTS);

                                        close(client_socket_fds[ii]);
                                    }
                                    if (parameters->log_file != NULL)
                                    {
                                        sm_log_close(parameters->log_file); //close log
                                    }
                                    sm_log_close(parameters->log_file);

                                    return;
                                }
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
                            char *confirm_client_msg = generate_confirm_msg(SERVER_MSG_BARRIER);
                            for (jj = 0; jj < barrier_count; ++jj)
                            {
                                protocol_write(client_socket_fds[jj], confirm_client_msg);
                            }
                            barrier_count = 0;
                            free(confirm_client_msg);
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
