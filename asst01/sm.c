
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "sm.h"
#include "commonlib.h"

#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>

#define PAGE_NUM 0xFFFF

static int host_id;
static int client_socket_fd;
static int fault_time;

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
    struct sm_ptr *msg = protocol_read(client_socket_fd);

    if (msg)
    {
        void **cmd_data = parse_msg(msg);

        if (!cmd_data)
        {
            free(msg->ptr);
            free(msg);
            printf("Invalid message received.\n");
            exit(EXIT_FAILURE);
        }

        char *cmd = (char *)cmd_data[0];
        struct sm_ptr *data = (struct sm_ptr *)cmd_data[1];

        if (!strcmp(SERVER_CMD_EXIT_CLIENTS, cmd)) // server notify all clients offline
        {
            sm_relase();
        }

        free(cmd);
        free(data->ptr);
        free(data);
        free(cmd_data);
        free(msg->ptr);
        free(msg);
    }
    else
    {
        printf("Cannot read from server\n");
        sm_relase();
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
    // int pagesize = getpagesize();
    // int sm_total = pagesize * PAGE_NUM;
    // char *sm_ptr = mmap(NULL, sm_total,
    //                     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
    //                     -1, 0);
    // char *nid_smptr = ;
    struct sm_ptr *data = malloc(sizeof(struct sm_ptr));
    data->ptr = &host_id;
    data->size = sizeof(host_id);
    struct sm_ptr *msg = generate_msg(CLIENT_CMD_REGISTER, data);
    free(data);
    protocol_write(client_socket_fd, msg);
    free(msg->ptr);
    free(msg);

    msg = protocol_read(client_socket_fd);

    if (!msg)
    {
        sm_relase();
        return -1;
    }

    void **cmd_data = parse_msg(msg);

    if (!cmd_data)
    {
        free(msg->ptr);
        free(msg);
        sm_relase();
        return -1;
    }

    char *cmd = (char *)cmd_data[0];
    data = (struct sm_ptr *)cmd_data[1];

    free(cmd);
    free(data->ptr);
    free(data);
    free(cmd_data);
    free(msg->ptr);
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
    struct sm_ptr *msg = generate_msg(CLIENT_CMD_EXIT, NULL);
    protocol_write(client_socket_fd, msg);
    free(msg->ptr);
    free(msg);

    sm_relase();
}


void handler (int signum, siginfo_t *si, void *ctx)
{
    void *addr;
    if (SIGSEGV != signum) {
        printf ("Panic!");
        exit (1);
    }
    addr = si->si_addr;       /* here we get the fault address */
    //printf ("...and the offending address is %p.\n", addr);
    fault_time++;
    if (fault_time == 1){
      printf("read_fault\n");

      struct sm_ptr *cmd_msg = generate_msg(READ_FAULT, addr);
      protocol_write(client_socket_fd, cmd_msg);
      free(cmd_msg->ptr);
      free(cmd_msg);
    }
    else if (fault_time == 2){
      printf("write_fault\n");
      struct sm_ptr *cmd_msg = generate_msg(WRITE_FAULT, addr);
      protocol_write(client_socket_fd, cmd_msg);
      free(cmd_msg->ptr);
      free(cmd_msg);
      fault_time = 0;
    }


    exit (0);
}

functuion receive_message(){
    struct sm_ptr *msg = protocol_read(client_socket_fd);
    if (msg){
      void **cmd_data = parse_msg(msg);
      char *cmd = (char *)cmd_data[0];
      struct sm_ptr *data = (struct sm_ptr *)cmd_data[1];
      if (!strcmp(to releasing ownership, cmd)){
        if (a has read permission ){
          mprotect(a, pagesize, PORT_READ);
        }else if (a has not read permission ){
          mprotect(a, pagesize, PORT_NONE);
        }
        struct sm_ptr *msg = generate_msg(releasing ownership, NULL);
        protocol_write(client_socket_fd, msg);
      }
      else if (!strcmp(giving you read permission, cmd)){
        mprotect(a, pagesize, PORT_READ);
        struct sm_ptr *msg = generate_msg(receiving read permission, NULL);
        protocol_write(client_socket_fd, msg);
      }


      else if (!strcmp(to invalidated, cmd)){
        mprotect(a, pagesize, PORT_NONE);
        struct sm_ptr *msg = generate_msg(react to invalidated, NULL);
        protocol_write(client_socket_fd, msg);
      }
      else if (!strcmp(giving you write permission, cmd)){
        mprotect(a, pagesize, PORT_WRITE);
        struct sm_ptr *msg = generate_msg(receiving ownership, NULL);
        protocol_write(client_socket_fd, msg);
      }
    }
}


void *sm_malloc(size_t size)
{
  struct sigaction sa;
  sa.sa_sigaction = handler;
  sa.sa_flags     = SA_SIGINFO;
  sigemptyset (&sa.sa_mask);
  sigaction (SIGSEGV, &sa, NULL);


    char * a;
    a = mmap (0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mprotect (a, 4096, PROT_NONE))
        perror ("mprotect");
    //printf("new mmap memory is %p\n," a);

    return a;

}

void sm_barrier(void)
{
    set_fd_sync(client_socket_fd);
    struct sm_ptr *msg = generate_msg(CLIENT_CMD_BARRIER, NULL);
    protocol_write(client_socket_fd, msg);
    free(msg->ptr);
    free(msg);

    while (true)
    {
        msg = protocol_read(client_socket_fd);
        if (msg)
        {
            void **cmd_data = parse_msg(msg);

            if (!cmd_data)
            {
                free(msg->ptr);
                free(msg);
                sm_relase();
                exit(EXIT_FAILURE);
            }

            char *cmd = (char *)cmd_data[0];
            struct sm_ptr *data = (struct sm_ptr *)cmd_data[1];

            if (is_confirm_cmd(cmd, CLIENT_CMD_BARRIER))
            {
                free(cmd);
                free(data->ptr);
                free(data);
                free(cmd_data);
                free(msg->ptr);
                free(msg);
                break;
            }

            free(cmd);
            free(data->ptr);
            free(data);
            free(cmd_data);
            free(msg->ptr);
            free(msg);
        }
        else
        {
            printf("Cannot read from server\n");
            sm_relase();
        }
    }
    set_fd_async(client_socket_fd);
}

void sm_bcast(void **addr, int root_nid)
{
}
