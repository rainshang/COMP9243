#include <signal.h>
#include <stdio.h>

#include "sm.h"
#include "commonlib.h"
#include <fcntl.h>

#define PAGE_NUM 0xFFFF

static int host_id;
static int client_socket_fd;

static void sm_relase()
{
    close(client_socket_fd);
}

static void sm_sigint_handler()
{
    sm_relase();
}

static void sm_sigpoll_handler()
{

    size_t msg_size;
    char *msg = protocol_read(client_socket_fd, &msg_size);

    if (msg_size > 0) // msg coming in
    {
        char **cmd_data;
        size_t data_size;

        cmd_data = parse_msg(msg, msg_size, &data_size);

        if (!cmd_data)
        {
            printf("Invalid message received.\n");

            exit(EXIT_FAILURE);
        }

        if (!strcmp(SERVER_CMD_EXIT_CLIENTS, cmd_data[0])) // server notify all clients offline
        {

            free(cmd_data[0]);
            free(cmd_data[1]);
            free(cmd_data);
            free(msg);
            kill(getppid(), SIGKILL);
            sm_relase();
            return;
        }

        free(cmd_data[0]);
        free(cmd_data[1]);
        free(cmd_data);
        free(msg);
    }
    else if (msg_size < 0 && check_errno()) //no msg, continue
    {
    }
    else //len_server_msg== 0
    {
        printf("Cannot read from server\n");
        kill(getppid(), SIGKILL);
        sm_relase();
        return;
    }
}

int sm_node_init(int *argc, char **argv[], int *nodes, int *nid)
{
    // parse arguments
    if (*argc < 5)
    {
        printf("Amount of argments is incomplete.\n");
        return -1;
    }

    const char *server_ip = (*argv)[1];
    int server_port;

    if (!sscanf((*argv)[2], "%d", &server_port))
    {
        perror("The 2nd argment should be an integer.\n");
        return -1;
    }
    if (!sscanf((*argv)[3], "%d", nodes))
    {
        perror("The 3th argment should be an integer.\n");
        return -1;
    }

    if (!sscanf((*argv)[4], "%d", nid))
    {
        perror("The 4th argment should be an integer.\n");
        return -1;
    }
    host_id = *nid;

    // printf("Host #%d: server IP is %s:%d, %d hosts totally. \n",
    //        *nid,
    //        server_ip,
    //        server_port,
    //        *nodes);

    //cut server info
    if (*argc > 5)
    {
        *argc -= 5;
        *argv += 5;
    }

    //connect socket
    if ((client_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
        perror("Client socket cannot create.");
        return -1;
    }

    struct sockaddr_in server_addr;
    init_sockaddr_in(&server_addr, server_ip, server_port);
    if (connect(client_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Cannot connect to server\n");
        return -1;
    }

    // register to server with nid
    size_t msg_size;
    char *cmd_data_msg = generate_msg(CLIENT_CMD_REGISTER, (char *)&host_id, sizeof(host_id), &msg_size);
    protocol_write(client_socket_fd, cmd_data_msg, msg_size);
    free(cmd_data_msg);

    char *msg = protocol_read(client_socket_fd, &msg_size);

    if (!msg)
    {
        sm_relase();
        return -1;
    }

    char **cmd_data;
    size_t data_size;
    cmd_data = parse_msg(msg, msg_size, &data_size);

    if (!cmd_data)
    {
        sm_relase();
        return -1;
    }

    free(cmd_data[0]);
    free(cmd_data[1]);
    free(cmd_data);
    free(msg);

    struct sigaction sa;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    sa.sa_handler = sm_sigpoll_handler;
    sigaction(SIGPOLL, &sa, NULL);

    sa.sa_handler = sm_sigint_handler;
    sigaction(SIGINT, &sa, NULL);

    set_fd_async(client_socket_fd);

    // printf("Host #%d: Connect to server successfully\n", *nid);
    return 0;
}

void sm_node_exit(void)
{
    size_t msg_size;
    char *cmd_msg = generate_msg(CLIENT_CMD_EXIT, NULL, 0, &msg_size);
    protocol_write(client_socket_fd, cmd_msg, msg_size);
    free(cmd_msg);

    sm_relase();
}

void *sm_malloc(size_t size)
{
    return NULL;
}

void sm_barrier(void)
{
    set_fd_sync(client_socket_fd);
    size_t msg_size;
    char *cmd_msg = generate_msg(CLIENT_CMD_BARRIER, NULL, 0, &msg_size);
    protocol_write(client_socket_fd, cmd_msg, msg_size);
    free(cmd_msg);

    while (true)
    {
        char *msg = protocol_read(client_socket_fd, &msg_size);
        if (msg_size > 0)
        {
            char **cmd_data;
            size_t data_size;

            cmd_data = parse_msg(msg, msg_size, &data_size);
            free(msg);

            if (!cmd_data)
            {
                printf("Invalid message received.\n");

                exit(EXIT_FAILURE);
            }

            if (is_confirm_cmd(cmd_data[0], CLIENT_CMD_BARRIER))
            {
                free(cmd_data[0]);
                free(cmd_data[1]);
                free(cmd_data);
                break;
            }
            free(cmd_data[0]);
            free(cmd_data[1]);
            free(cmd_data);
            break;
        }
    }
    set_fd_async(client_socket_fd);
}

void sm_bcast(void **addr, int root_nid)
{
}