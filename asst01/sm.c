#include <signal.h>

#include "sm.h"
#include "commonlib.h"

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
    char server_msg[BUFSIZ];
    int len_server_msg = protocol_read(client_socket_fd, server_msg);

    if (len_server_msg > 0) // msg coming in
    {
        // printf("#%d: msg from server: %s\n", host_id, server_msg);
        // protocol_write(client_socket_fd, generate_client_msg(host_id, server_msg));

        if (!strcmp(SERVER_MSG_EXIT_CLIENTS, server_msg)) // server notify all clients offline
        {
            kill(getppid(), SIGKILL);
            sm_relase();
            return;
        }
    }
    else if (len_server_msg < 0 && check_errno()) //no msg, continue
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
    char *msg_send = generate_client_msg(host_id, CLIENT_MSG_REGISTER);
    protocol_write(client_socket_fd, msg_send);
    free(msg_send);
    char server_msg[BUFSIZ];
    int len_server_msg = protocol_read(client_socket_fd, server_msg);

    if (!len_server_msg)
    {
        sm_relase();
        return -1;
    }
    if (!is_confirm_msg(server_msg, CLIENT_MSG_REGISTER))
    {
        sm_relase();
        return -1;
    }

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
    char *msg_send = generate_client_msg(host_id, CLIENT_MSG_EXIT);
    protocol_write(client_socket_fd, msg_send);
    free(msg_send);
    sm_relase();
}

void *sm_malloc(size_t size)
{
    return NULL;
}

void sm_barrier(void)
{
    set_fd_sync(client_socket_fd);
    char *msg_send = generate_client_msg(host_id, SERVER_MSG_BARRIER);
    protocol_write(client_socket_fd, msg_send);
    free(msg_send);

    while (true)
    {
        char server_ms[BUFSIZ];
        int len = protocol_read(client_socket_fd, server_ms);
        if (len > 0)
        {
            if (is_confirm_msg(server_ms, SERVER_MSG_BARRIER))
            {
                break;
            }
        }
    }
    set_fd_async(client_socket_fd);
}

void sm_bcast(void **addr, int root_nid)
{
}