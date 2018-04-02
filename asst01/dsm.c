#include <sys/socket.h>
#include <stdint.h>

#include "param.h"
#include "commonlib.h"
#include "vec.h"

typedef struct sm_permission
{
    void *ptr; // address of each mempry sm_malloc()ed
    int has_write_permission_node;
    int *has_read_permission_nodes;
} sm_permission;

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
    // set timeout for accept
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
                    if (DEBUG)
                    {
                        allocator_printf("SSH process pid is %d\n", pid_ssh);
                    }

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
                    if (DEBUG)
                    {
                        allocator_printf("main process pid is %d\n", getpid());
                    }

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
                        client_nids[ii] = ii; // will be set by client msg
                        set_fd_nonblock(client_socket_fds[ii]);
                    }

                    // block cmd action counter
                    unsigned count_offline_host = 0;
                    unsigned count_barriered = 0;
                    unsigned count_registered = 0;
                    unsigned count_aligned = 0;
                    unsigned count_bcasted = 0;
                    // shared memory management
                    void *aligned_sm_start_addr = UINTPTR_MAX; //select the minimum as the aligned address
                    unsigned pagesize;                         // pagesize of node machine
                    void *unmalloc_sm_addr;                    // current available
                    vec_void_t sm_permission_vector;           // to store all the addresses in sm
                    // for sm_bcast
                    int bcast_node_index;
                    void *bcast_addr = NULL;
                    size_t bcast_size;
                    // int target_release_ownership = -1;
                    // int current_want_read_node = -1;
                    // int target_release_ownership_index;
                    // int current_want_read_node_index;
                    int current_want_write_node;
                    int current_want_write_node_index;

                    int current_want_read_node;
                    int current_want_read_node_index;
                    int target_release_ownership;
                    int target_release_ownership_index;
                    int release_ownership_node;
                    int read_list_len = 0;
                    int invalidated_count = 0;

                    int lock = 0;
                    vec_void_t read_fault_queue;
                    vec_init(&read_fault_queue);

                    while (true)
                    {
                        // check offline
                        count_offline_host = 0;
                        for (ii = 0; ii < parameters->host_num; ++ii)
                        {
                            if (!client_socket_fds[ii])
                            {
                                ++count_offline_host;
                            }
                        }
                        if (count_offline_host == parameters->host_num) // all the host offline
                        {
                            // TODO release
                            if (parameters->log_file != NULL)
                            {
                                sm_log_close(parameters->log_file); //close log
                            }
                            return;
                        }
                        // normally read msg
                        for (ii = 0; ii < parameters->host_num; ++ii)
                        {
                            if (client_socket_fds[ii])
                            {
                                int len;
                                struct sm_ptr *msg;
                                if (read_fault_queue.length > 0 && lock != 0)
                                {
                                    allocator_printf("come in queue....\n");
                                    msg = (struct sm_ptr *)vec_pop(&read_fault_queue);
                                }
                                else
                                {
                                    msg = protocol_read(client_socket_fds[ii], &len);
                                }

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
                                        allocator_printf("#%d: ", client_nids[ii]);
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
                                        memcpy(&pagesize, data->ptr + sizeof(client_nids[ii]), sizeof(pagesize));
                                        void *sm_addr;
                                        memcpy(&sm_addr, data->ptr + sizeof(client_nids[ii]) + sizeof(pagesize), sizeof(sm_addr));
                                        if (DEBUG)
                                        {
                                            allocator_printf("a native sm_address is %p\n", sm_addr);
                                        }
                                        if (sm_addr < aligned_sm_start_addr)
                                        {
                                            aligned_sm_start_addr = sm_addr;
                                        }
                                        if (DEBUG)
                                        {
                                            allocator_printf("current aligned sm_address is %p\n", aligned_sm_start_addr);
                                        }
                                        ++count_registered;
                                        if (count_registered == parameters->host_num) //all nodes have registered
                                        {
                                            free(data->ptr);
                                            free(data);

                                            data = malloc(sizeof(struct sm_ptr));
                                            data->size = sizeof(aligned_sm_start_addr);
                                            char *data_ptr = malloc(data->size);
                                            memcpy(data_ptr, &aligned_sm_start_addr, sizeof(aligned_sm_start_addr));
                                            data->ptr = data_ptr; // data:{aligned_sm_start_addr}
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
                                        if (count_aligned == 0)
                                        {
                                            aligned_sm_start_addr = sm_addr;
                                        }
                                        ++count_aligned;

                                        if (aligned_sm_start_addr != sm_addr || count_aligned == parameters->host_num)
                                        {
                                            free(data->ptr);
                                            free(data);

                                            bool is_align_success;
                                            data = malloc(sizeof(struct sm_ptr));
                                            data->size = sizeof(is_align_success);
                                            char *data_ptr = malloc(data->size);

                                            if (aligned_sm_start_addr != sm_addr)
                                            {
                                                is_align_success = false;
                                            }
                                            else if (count_aligned == parameters->host_num)
                                            {
                                                is_align_success = true;
                                                unmalloc_sm_addr = aligned_sm_start_addr;
                                                allocator_printf("final aligned sm_address is %p\n", aligned_sm_start_addr);
                                                vec_init(&sm_permission_vector);
                                            }

                                            memcpy(data_ptr, &is_align_success, sizeof(is_align_success));
                                            data->ptr = data_ptr; // data:{is_align_success}
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
                                    else if (!strcmp(CLIENT_CMD_MALLOC, cmd))
                                    {
                                        size_t size;
                                        memcpy(&size, data->ptr, sizeof(size));
                                        if (DEBUG)
                                        {
                                            allocator_printf("%d node apply for allocating %d bytes memory\n", client_nids[ii], size);
                                        }

                                        unsigned need_page = (size - size % pagesize) / pagesize + 1;
                                        void *sendback_sm_addr;

                                        if (unmalloc_sm_addr + pagesize * need_page < aligned_sm_start_addr + pagesize * PAGE_NUM)
                                        {
                                            sendback_sm_addr = unmalloc_sm_addr;
                                            unmalloc_sm_addr += pagesize * need_page;
                                        }
                                        else // out of bounds
                                        {
                                            sendback_sm_addr = 0;
                                        }

                                        free(data->ptr);
                                        free(data);

                                        data = malloc(sizeof(struct sm_ptr));
                                        data->size = sizeof(sendback_sm_addr);
                                        char *data_ptr = malloc(data->size);
                                        memcpy(data_ptr, &sendback_sm_addr, sizeof(sendback_sm_addr));
                                        data->ptr = data_ptr; // data:{sendback_sm_addr}
                                        char *confirm_cmd = generate_confirm_cmd(CLIENT_CMD_MALLOC);
                                        msg = generate_msg(confirm_cmd, data);
                                        free(confirm_cmd);
                                        protocol_write(client_socket_fds[ii], msg);
                                        free(msg->ptr);
                                        free(msg);
                                    }
                                    else if (!strcmp(CLIENT_CMD_EXIT, cmd)) // receive sm_node_exit() from nid, then server wait for all host send this
                                    {
                                        // set this offline
                                        close(client_socket_fds[ii]);
                                        client_socket_fds[ii] = 0;
                                    }
                                    else if (!strcmp(CLIENT_CMD_BARRIER, cmd))
                                    {
                                        ++count_barriered;

                                        if (count_barriered == parameters->host_num)
                                        {
                                            char *confirm_cmd = generate_confirm_cmd(CLIENT_CMD_BARRIER);
                                            msg = generate_msg(confirm_cmd, NULL);
                                            free(confirm_cmd);
                                            unsigned iii;
                                            for (iii = 0; iii < parameters->host_num; ++iii)
                                            {
                                                protocol_write(client_socket_fds[iii], msg);
                                            }
                                            free(msg->ptr);
                                            free(msg);
                                            count_barriered = 0;
                                        }
                                    }
                                    else if (!strcmp(CLIENT_CMD_BROADCAST, cmd))
                                    {
                                        ++count_bcasted;

                                        if (data->size > 0) //is the node who sm_malloced the address
                                        {
                                            bcast_node_index = ii;
                                            memcpy(&bcast_addr, data->ptr, sizeof(bcast_addr));
                                            memcpy(&bcast_size, data->ptr + sizeof(bcast_addr), sizeof(bcast_size));
                                        }

                                        if (count_bcasted == parameters->host_num)
                                        {
                                            char *confirm_cmd = generate_confirm_cmd(CLIENT_CMD_BROADCAST);
                                            struct sm_ptr *msg0 = generate_msg(confirm_cmd, NULL);
                                            free(data->ptr);
                                            free(data);
                                            data = malloc(sizeof(struct sm_ptr));
                                            data->size = sizeof(bcast_addr) + sizeof(bcast_size);
                                            char *data_ptr = malloc(data->size);
                                            memcpy(data_ptr, &bcast_addr, sizeof(bcast_addr));
                                            memcpy(data_ptr + sizeof(bcast_addr), &bcast_size, sizeof(bcast_size));
                                            data->ptr = data_ptr; // data:{bcast_addr}{bcast_size}
                                            struct sm_ptr *msg1 = generate_msg(confirm_cmd, data);
                                            free(confirm_cmd);
                                            unsigned iii;
                                            int tmp_read_nodes[parameters->host_num];
                                            for (iii = 0; iii < parameters->host_num; ++iii)
                                            {
                                                if (iii == bcast_node_index)
                                                {
                                                    protocol_write(client_socket_fds[iii], msg0);
                                                }
                                                else
                                                {
                                                    protocol_write(client_socket_fds[iii], msg1);
                                                }
                                                tmp_read_nodes[iii] = -1;
                                            }
                                            struct sm_permission *smper = malloc(sizeof(struct sm_permission));
                                            smper->ptr = bcast_addr;
                                            smper->has_write_permission_node = client_nids[bcast_node_index];
                                            smper->has_read_permission_nodes = tmp_read_nodes;
                                            smper->has_read_permission_nodes[0] = client_nids[bcast_node_index];
                                            // allocator_printf("=======%d\n", smper->has_read_permission_nodes[1]);
                                            // exit(EXIT_FAILURE);
                                            vec_push(&sm_permission_vector, smper);
                                            if (DEBUG)
                                            {
                                                allocator_printf("#%d has sm_bcasted it's address %p\n", client_nids[bcast_node_index], bcast_addr);
                                            }
                                            free(msg0->ptr);
                                            free(msg0);
                                            free(msg1->ptr);
                                            free(msg1);
                                            count_bcasted = 0;
                                        }
                                    }
                                    else if (!strcmp(READ_FAULT, cmd))
                                    {
                                        // if (DEBUG) {
                                        //   allocator_printf("receive read fault from %d\n", client_nids[ii]);
                                        // }
                                        allocator_printf("++++++%d\n", lock);

                                        if (lock == 1)
                                        {
                                            struct sm_ptr *msg = generate_msg(READ_FAULT, data);
                                            vec_push(&read_fault_queue, msg);
                                            allocator_printf("inser to queue");
                                        }
                                        else
                                        {

                                            char flag;
                                            memcpy(&flag, data->ptr, sizeof(char));

                                            allocator_printf("=====%s\n", &flag);

                                            if (flag == 'r')
                                            {
                                                memcpy(&current_want_read_node, data->ptr + sizeof(char), sizeof(int));

                                                if (DEBUG)
                                                {
                                                    allocator_printf("receive read fault from %d\n", current_want_read_node);
                                                }
                                                int ii;
                                                for (ii = 0; ii < parameters->host_num; ++ii)
                                                {
                                                    if (client_nids[ii] == current_want_read_node)
                                                    {
                                                        current_want_read_node_index = ii;
                                                    }
                                                }
                                                int i;
                                                struct sm_permission *smper = malloc(sizeof(struct sm_permission));
                                                void *receive_data;
                                                memcpy(&receive_data, data->ptr + sizeof(char) + sizeof(int), sizeof(void *));
                                                //bool flag = false;
                                                for (i = 0; i < sm_permission_vector.length; ++i)
                                                {
                                                    smper = (struct sm_permission *)sm_permission_vector.data[i];
                                                    if (smper->ptr == receive_data)
                                                    {
                                                        if (smper->has_write_permission_node >= 0)
                                                        {
                                                            target_release_ownership = smper->has_write_permission_node;
                                                            smper->has_write_permission_node = -1;
                                                            int jj;
                                                            for (jj = 0; jj < parameters->host_num; ++jj)
                                                            {
                                                                allocator_printf("%p=======%d\n", receive_data, smper->has_read_permission_nodes[jj]);
                                                                if (smper->has_read_permission_nodes[jj] == -1)
                                                                {
                                                                    smper->has_read_permission_nodes[jj] = current_want_read_node;

                                                                    break;
                                                                }
                                                            }
                                                            //flag = true;
                                                        }
                                                        else
                                                        {
                                                            int jj;
                                                            for (jj = parameters->host_num - 1; jj >= 0; --jj)
                                                            {
                                                                if (smper->has_read_permission_nodes[jj] != -1)
                                                                {
                                                                    allocator_printf("%p*****%d\n", receive_data, smper->has_read_permission_nodes[jj]);
                                                                    target_release_ownership = smper->has_read_permission_nodes[jj];
                                                                    //allocator_printf("*******%d\n", smper->has_read_permission_nodes[ii]);
                                                                    int k;
                                                                    for (k = 0; k < parameters->host_num; ++k)
                                                                    {
                                                                        if (smper->has_read_permission_nodes[k] == -1)
                                                                        {
                                                                            smper->has_read_permission_nodes[k] = current_want_read_node;
                                                                            break;
                                                                        }
                                                                    }
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                struct sm_ptr *msg = generate_msg(RELEASE_OENERSHIP, data);
                                                int ij;
                                                for (ij = 0; ij < parameters->host_num; ++ij)
                                                {
                                                    if (client_nids[ij] == target_release_ownership)
                                                    {
                                                        target_release_ownership_index = ij;
                                                        break;
                                                    }
                                                }
                                                protocol_write(client_socket_fds[target_release_ownership_index], msg);
                                                // allocator_printf("node %d request to read ...\n", client_nids[current_want_read_node_index]);
                                                allocator_printf("%d has send release ownership to  %d....\n", client_nids[current_want_read_node_index], client_nids[target_release_ownership_index]);
                                            }
                                            else if (flag == 'c')
                                            {
                                                lock = 1;
                                                memcpy(&release_ownership_node, data->ptr + sizeof(char), sizeof(int));
                                                if (DEBUG)
                                                {
                                                    allocator_printf("receive ownership from %d\n", release_ownership_node);
                                                }
                                                void *receive_data_address;
                                                memcpy(&receive_data_address, data->ptr + sizeof(char) + sizeof(int), sizeof(void *));
                                                struct sm_ptr *receive_data_content = malloc(sizeof(struct sm_ptr));
                                                receive_data_content->size = data->size - sizeof(void *) - sizeof(char) - sizeof(int);
                                                receive_data_content->ptr = malloc(receive_data_content->size);
                                                memcpy(receive_data_content->ptr, data->ptr + sizeof(void *) + sizeof(char) + sizeof(int), receive_data_content->size);

                                                char *confirm_cmd = generate_confirm_cmd(GIVING_READ_PERMISSION);

                                                data = malloc(sizeof(struct sm_ptr));
                                                data->size = receive_data_content->size;
                                                char *data_ptr = malloc(data->size);
                                                memcpy(data_ptr, receive_data_content->ptr, receive_data_content->size);
                                                data->ptr = data_ptr;
                                                struct sm_ptr *msg = generate_msg(confirm_cmd, data);

                                                protocol_write(client_socket_fds[current_want_read_node_index], msg);
                                                allocator_printf("has send read permission to %d....\n", client_nids[current_want_read_node_index]);
                                                lock = 0;
                                            }
                                        }
                                    }

                                    // if (lock2 > 0){
                                    //   struct sm_ptr *msg = generate_msg(READ_FAULT, data);
                                    //   vec_push(&read_fault_queue, msg);
                                    // }
                                    // else{
                                    // //lock1 = 1;
                                    //
                                    // current_want_read_node = client_nids[ii];
                                    // int i;
                                    // current_want_read_node_index = ii;
                                    //
                                    // struct sm_permission *smper = malloc(sizeof(struct sm_permission));
                                    // void *receive_data;
                                    //
                                    // memcpy(&receive_data, data->ptr, sizeof(void*));
                                    // //bool flag = false;
                                    // for (i=0; i<sm_permission_vector.length; ++i){
                                    //   smper = (struct sm_permission *)sm_permission_vector.data[i];
                                    //   if (smper->ptr == receive_data){
                                    //     if (smper->has_write_permission_node >= 0) {
                                    //         target_release_ownership = smper->has_write_permission_node;
                                    //         smper->has_write_permission_node = -1;
                                    //         int jj;
                                    //         for (jj=0; jj<parameters->host_num; ++jj){
                                    //           allocator_printf("%p=======%d\n", receive_data, smper->has_read_permission_nodes[jj]);
                                    //           if (smper->has_read_permission_nodes[jj] == -1){
                                    //             smper->has_read_permission_nodes[jj] = current_want_read_node;
                                    //
                                    //             break;
                                    //           }
                                    //         }
                                    //         //flag = true;
                                    //     }
                                    //     else{
                                    //       int ii;
                                    //       for (ii=parameters->host_num-1; ii>=0; --ii){
                                    //         if (smper->has_read_permission_nodes[ii] != -1){
                                    //           allocator_printf("%p*****%d\n", receive_data, smper->has_read_permission_nodes[ii]);
                                    //           target_release_ownership = smper->has_read_permission_nodes[ii];
                                    //           //allocator_printf("*******%d\n", smper->has_read_permission_nodes[ii]);
                                    //           int jj;
                                    //           for (jj=0; jj<parameters->host_num; ++jj){
                                    //             if (smper->has_read_permission_nodes[jj] == -1){
                                    //               smper->has_read_permission_nodes[jj] = current_want_read_node;
                                    //               break;
                                    //             }
                                    //           }
                                    //            break;
                                    //         }
                                    //       }
                                    //     }
                                    //   }
                                    // }
                                    // struct sm_ptr *msg = generate_msg(RELEASE_OENERSHIP, data);
                                    // int ij;
                                    // for (ij=0; ij<parameters->host_num; ++ij){
                                    //   if (client_nids[ij] == target_release_ownership){
                                    //     target_release_ownership_index = ij;
                                    //     break;
                                    //   }
                                    // }
                                    // protocol_write(client_socket_fds[target_release_ownership_index], msg);
                                    // allocator_printf("node %d request to read ...\n", client_nids[current_want_read_node_index]);
                                    // allocator_printf("%d has send release ownership to  %d....\n", client_nids[ii], client_nids[target_release_ownership_index]);
                                    // if (client_nids[current_want_read_node] == 0){
                                    //   allocator_printf("==========%p\n", receive_data);
                                    //   exit(EXIT_FAILURE);
                                    // }
                                    // free(msg->ptr);
                                    // free(msg);
                                    // free(receive_data);
                                    // free(smper->ptr);
                                    // free(smper);
                                    // free(data->ptr);
                                    // free(data);
                                    //}
                                    //   lock1 = 0;
                                    // }
                                    // }
                                    else if (!strcmp(HAVE_RELEASED_OWNERSHIP, cmd))
                                    {
                                        if (DEBUG)
                                        {
                                            allocator_printf("receive ownership from %d\n", client_nids[ii]);
                                        }

                                        void *receive_data_address;
                                        memcpy(&receive_data_address, data->ptr, sizeof(void *));
                                        struct sm_ptr *receive_data_content = malloc(sizeof(struct sm_ptr));
                                        receive_data_content->size = data->size - sizeof(void *);
                                        receive_data_content->ptr = malloc(receive_data_content->size);
                                        memcpy(receive_data_content->ptr, data->ptr + sizeof(void *), receive_data_content->size);

                                        char *confirm_cmd = generate_confirm_cmd(GIVING_READ_PERMISSION);

                                        data = malloc(sizeof(struct sm_ptr));
                                        data->size = receive_data_content->size;
                                        char *data_ptr = malloc(data->size);
                                        memcpy(data_ptr, receive_data_content->ptr, receive_data_content->size);
                                        data->ptr = data_ptr;
                                        struct sm_ptr *msg = generate_msg(confirm_cmd, data);

                                        // int k;
                                        // struct sm_permission *smper = malloc(sizeof(struct sm_permission));
                                        // for (k=0; k<sm_permission_vector.length; ++k) {
                                        //    smper = (struct sm_permission *)sm_permission_vector.data[k];
                                        //    if (smper->ptr == receive_data_address){
                                        //      //smper->has_write_permission_node = -1;
                                        //      int jj;
                                        //      for (jj=0; jj<parameters->host_num; ++jj){
                                        //        if (smper->has_read_permission_nodes[jj] == -1){
                                        //          smper->has_read_permission_nodes[jj] = current_want_read_node;
                                        //          break;
                                        //        }
                                        //      }
                                        //    }
                                        // }
                                        protocol_write(client_socket_fds[current_want_read_node_index], msg);
                                        allocator_printf("%d has send read permission to %d....\n", client_nids[ii], client_nids[current_want_read_node_index]);

                                        // allocator_printf("*****%d\n", current_want_read_node);
                                        // exit(EXIT_FAILURE);
                                        //
                                        //  free(msg->ptr);
                                        //  free(msg);
                                        //  free(receive_data_address);
                                        // free(receive_data_content->ptr);
                                        //  free(receive_data_content);
                                        // free(data->ptr);
                                        // free(data);

                                        current_want_read_node = -1;
                                        current_want_read_node_index = -1;
                                        target_release_ownership = -1;
                                        target_release_ownership_index = -1;
                                    }
                                    else if (!strcmp(WRITE_FAULT, cmd))
                                    {
                                        if (DEBUG)
                                        {
                                            allocator_printf("receive write fault from %d\n", client_nids[ii]);
                                        }
                                        current_want_write_node = client_nids[ii];
                                        current_want_write_node_index = ii;

                                        struct sm_permission *smper = malloc(sizeof(struct sm_permission));
                                        void *receive_data;
                                        memcpy(&receive_data, data->ptr, sizeof(void *));
                                        int i;
                                        for (i = 0; i < sm_permission_vector.length; ++i)
                                        {
                                            smper = (struct sm_permission *)sm_permission_vector.data[i];
                                            if (smper->ptr == receive_data)
                                            {
                                                int jj;
                                                struct sm_ptr *msg = generate_msg(GIVE_UP_READ_PERMISSION, data);
                                                for (jj = 0; jj < parameters->host_num; ++jj)
                                                {
                                                    if (smper->has_read_permission_nodes[jj] != -1 && smper->has_read_permission_nodes[jj] != current_want_write_node)
                                                    {
                                                        ++read_list_len;
                                                        int target_node_id = smper->has_read_permission_nodes[jj];
                                                        int jjj;
                                                        for (jjj = 0; jjj < parameters->host_num; ++jjj)
                                                        {
                                                            if (client_nids[jjj] == target_node_id)
                                                            {
                                                                protocol_write(client_socket_fds[jjj], msg);
                                                            }
                                                        }
                                                    }
                                                    else if (smper->has_read_permission_nodes[jj] != -1)
                                                    {
                                                        smper->has_read_permission_nodes[jj] = -1;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    else if (!strcmp(INVALIDATED, cmd))
                                    {
                                        if (DEBUG)
                                        {
                                            allocator_printf("receive invalited from %d\n", client_nids[ii]);
                                        }
                                        ++invalidated_count;
                                        //allocator_printf("read_list_len = %d, invalidated_count = %d\n", read_list_len, invalidated_count);

                                        if (read_list_len == invalidated_count)
                                        {
                                            struct sm_permission *smper = malloc(sizeof(struct sm_permission));
                                            void *receive_data;
                                            memcpy(&receive_data, data->ptr, sizeof(void *));
                                            int i;
                                            for (i = 0; i < sm_permission_vector.length; ++i)
                                            {
                                                smper = (struct sm_permission *)sm_permission_vector.data[i];
                                                if (smper->ptr == receive_data)
                                                {
                                                    smper->has_write_permission_node = current_want_write_node;
                                                }
                                            }
                                            struct sm_ptr *msg = generate_msg(GIVE_WRITE_PERMISSION, data);
                                            protocol_write(client_socket_fds[current_want_write_node_index], msg);
                                            read_list_len = 0;
                                            invalidated_count = 0;
                                        }
                                    }

                                    free(cmd);
                                    free(data->ptr);
                                    free(data);
                                    free(cmd_data);
                                }
                                else if (len != 0 && is_read_dault_acceptable())
                                {
                                    // continue
                                }
                                else // connection break
                                {
                                    if (DEBUG)
                                    {
                                        allocator_printf("#%d: disconnected\n", client_nids[ii]);
                                    }
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
