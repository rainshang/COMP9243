
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>

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

static unsigned sm_total_size;
static void *aligned_sm_addr;

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
        free(msg->ptr);
        free(msg);

        if (!cmd_data)
        {
            node_printf(host_id, "Invalid message received.\n");
            sm_relase();
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
    }
    else
    {
        node_printf(host_id, "Cannot read from allocator\n");
        sm_relase();
    }
}

static int parse_param_and_connect(int *argc, char **argv[], int *nodes, int *nid)
{
    if (*argc < 5)
    {
        printf("Amount of argments is incomplete.\n");
        return -1;
    }

    const char *server_ip = (*argv)[1];
    int server_port;

    if (!sscanf((*argv)[2], "%d", &server_port))
    {
        printf("The 2nd argment should be an integer.\n");
        return -1;
    }
    if (!sscanf((*argv)[3], "%d", nodes))
    {
        printf("The 3th argment should be an integer.\n");
        return -1;
    }

    if (!sscanf((*argv)[4], "%d", nid))
    {
        printf("The 4th argment should be an integer.\n");
        return -1;
    }
    host_id = *nid;

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
        perror("Cannot connect to allocator\n");
        return -1;
    }
    return 0;
}

<<<<<<< HEAD
    // register to server with nid and available shared memeory address
    // int pagesize = getpagesize();
    // int sm_total = pagesize * PAGE_NUM;
    // // let system allocate the available shared free memonry
    // void *sm_addr = mmap(NULL, sm_total,
    //                      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
    //                      -1, 0);
    // if (DEBUG)
    // {
    //     node_printf(host_id, "native available sm_address is %p\n", sm_addr);
    // }
    // struct sm_ptr *data = malloc(sizeof(struct sm_ptr));
    // data->size = sizeof(host_id) + sizeof(sm_addr);
    // char *data_ptr = malloc(data->size);
    // memcpy(data_ptr, &host_id, sizeof(host_id));
    // memcpy(data_ptr + sizeof(host_id), &sm_addr, sizeof(sm_addr));
    // data->ptr = data_ptr; // data: {host_id}{sm_addr}
    // struct sm_ptr *msg = generate_msg(CLIENT_CMD_REGISTER, data);
    // free(data->ptr);
    // free(data);
    // protocol_write(client_socket_fd, msg);
    // free(msg->ptr);
    // free(msg);
    //
    // msg = protocol_read(client_socket_fd);
    //
    // if (!msg)
    // {
    //     node_printf(host_id, "cannot read from allocator\n");
    //     sm_relase();
    //     return -1;
    // }
    //
    // void **cmd_data = parse_msg(msg);
    // free(msg->ptr);
    // free(msg);
    //
    // if (!cmd_data)
    // {
    //     node_printf(host_id, "Invalid message received.\n");
    //     sm_relase();
    //     return -1;
    // }
    //
    // char *cmd = (char *)cmd_data[0];
    // data = (struct sm_ptr *)cmd_data[1]; // aligned shared memory address
    // bool is_register_success = is_confirm_cmd(cmd, CLIENT_CMD_REGISTER);
    // if (is_register_success)
    // {
    //     memcpy(&aligned_sm_addr, data->ptr, data->size);
    // }
    // free(cmd);
    // free(data->ptr);
    // free(data);
    // free(cmd_data);
    // if (!is_register_success)
    // {
    //     node_printf(host_id, "Unexpected command received.\n");
    //     sm_relase();
    //     return -1;
    // }
    // if (DEBUG)
    // {
    //     node_printf(host_id, "aligned available sm_address is %p\n", aligned_sm_addr);
    // } // register done
=======
static int register_nid_native_sm_addr(void **sm_addr)
{
    // let system allocate the available shared free memonry
    *sm_addr = mmap(NULL, sm_total_size,
                    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                    -1, 0);
    if (DEBUG)
    {
        node_printf(host_id, "native available sm_address is %p\n", *sm_addr);
    }
    struct sm_ptr *data = malloc(sizeof(struct sm_ptr));
    data->size = sizeof(host_id) + sizeof(sm_total_size) + sizeof(sm_addr);
    char *data_ptr = malloc(data->size);
    memcpy(data_ptr, &host_id, sizeof(host_id));
    memcpy(data_ptr + sizeof(host_id), &sm_total_size, sizeof(sm_total_size));
    memcpy(data_ptr + sizeof(host_id) + sizeof(sm_total_size), sm_addr, sizeof(sm_addr));
    data->ptr = data_ptr; // data: {host_id}{sm_total_size}{sm_addr}
    struct sm_ptr *msg = generate_msg(CLIENT_CMD_REGISTER, data);
    free(data->ptr);
    free(data);
    protocol_write(client_socket_fd, msg);
    free(msg->ptr);
    free(msg);

    msg = protocol_read(client_socket_fd);

    if (!msg)
    {
        node_printf(host_id, "cannot read from allocator\n");
        sm_relase();
        return -1;
    }

    void **cmd_data = parse_msg(msg);
    free(msg->ptr);
    free(msg);

    if (!cmd_data)
    {
        node_printf(host_id, "Invalid message received.\n");
        sm_relase();
        return -1;
    }

    char *cmd = (char *)cmd_data[0];
    data = (struct sm_ptr *)cmd_data[1]; // {aligned shared memory address}
    bool is_ccm = is_confirm_cmd(cmd, CLIENT_CMD_REGISTER);
    if (is_ccm)
    {
        memcpy(&aligned_sm_addr, data->ptr, data->size);
    }
    free(cmd);
    free(data->ptr);
    free(data);
    free(cmd_data);
    if (!is_ccm)
    {
        node_printf(host_id, "Unexpected command received.\n");
        sm_relase();
        return -1;
    }
    if (DEBUG)
    {
        node_printf(host_id, "first aligned available sm_address is %p\n", aligned_sm_addr);
    }
    return 0;
}

static int align_sm_addr(void *native_sm_addr)
{
    munmap(native_sm_addr, sm_total_size); // free the first try
    aligned_sm_addr = mmap(aligned_sm_addr, sm_total_size,
                           PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                           -1, 0);
    if (MAP_FAILED == aligned_sm_addr)
    {
        perror("Cannot mmap the entire shared memeory");
        sm_relase();
        return -1;
    }

    struct sm_ptr *data = malloc(sizeof(struct sm_ptr));
    data->size = sizeof(aligned_sm_addr);
    char *data_ptr = malloc(data->size);
    memcpy(data_ptr, &aligned_sm_addr, sizeof(aligned_sm_addr));
    data->ptr = data_ptr; // data: {aligned_sm_addr}
    struct sm_ptr *msg = generate_msg(CLIENT_CMD_ALIGN, data);
    free(data->ptr);
    free(data);
    protocol_write(client_socket_fd, msg);
    free(msg->ptr);
    free(msg);

    msg = protocol_read(client_socket_fd);

    if (!msg)
    {
        node_printf(host_id, "cannot read from allocator\n");
        sm_relase();
        return -1;
    }

    void **cmd_data = parse_msg(msg);
    free(msg->ptr);
    free(msg);

    if (!cmd_data)
    {
        node_printf(host_id, "Invalid message received.\n");
        sm_relase();
        return -1;
    }

    char *cmd = (char *)cmd_data[0];
    data = (struct sm_ptr *)cmd_data[1]; // {bool}
    bool is_ccmd = is_confirm_cmd(cmd, CLIENT_CMD_ALIGN);
    bool is_align_success;
    if (is_ccmd)
    {
        memcpy(&is_align_success, data->ptr, data->size);
    }
    free(cmd);
    free(data->ptr);
    free(data);
    free(cmd_data);
    if (!is_ccmd)
    {
        node_printf(host_id, "Unexpected command received.\n");
        sm_relase();
        return -1;
    }
    if (!is_align_success) //allocator find not same
    {
        munmap(aligned_sm_addr, sm_total_size); // free the second try
        sm_relase();
        return -1;
    }
    return 0;
}

int sm_node_init(int *argc, char **argv[], int *nodes, int *nid)
{
    // parse arguments
    if (parse_param_and_connect(argc, argv, nodes, nid))
    {
        return -1;
    }

    int pagesize = getpagesize();
    sm_total_size = pagesize * PAGE_NUM;

    // register to server with nid and native available shared memeory address
    void *native_sm_addr;
    if (register_nid_native_sm_addr(&native_sm_addr))
    {
        return -1;
    }
    // re-mmap() the aligned sm_addr, system will aligns it slightly by page_size, then double check with allocator that all the nodes are same
    if (align_sm_addr(native_sm_addr))
    {
        return -1;
    }
    // finally, we got a universal aligned sm_addr
    node_printf(host_id, "final aligned available sm_address is %p\n", aligned_sm_addr);
>>>>>>> 30a6a3020add3288ba3f8408387465031d5cd144

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
    set_fd_sync(client_socket_fd);
    void *addr;
    if (SIGSEGV != signum) {
        printf ("Panic!");
        exit (1);
    }

    addr = si->si_addr;       /* here we get the fault address */
    //Cannot read from allocatorprintf ("...and the offending address is %p.\n", addr);

      struct sm_ptr *data = malloc(sizeof(struct sm_ptr));
      data->size = sizeof(addr);
      char *data_ptr = malloc(data->size);
      memcpy(data_ptr, &addr, sizeof(addr));
      data->ptr = data_ptr;

      struct sm_ptr *msg = generate_msg(READ_FAULT, data);
      free(data->ptr);
      free(data);
      protocol_write(client_socket_fd, msg);
      free(msg->ptr);
      free(msg);

      msg = protocol_read(client_socket_fd);
      if (msg)
      {
          void **cmd_data = parse_msg(msg);
          free(msg->ptr);
          free(msg);

          if (!cmd_data)
          {
              sm_relase();
              exit(EXIT_FAILURE);
          }

          char *cmd = (char *)cmd_data[0];
          data = (struct sm_ptr *)cmd_data[1];
          if (is_confirm_cmd(cmd, CMD_READ_FAULT))
          {
            mprotect (addr, 4096, PROT_READ|PROT_WRITE);
          }
          free(cmd);
          free(data->ptr);
          free(data);
          free(cmd_data);
      }
      else
      {
          node_printf(host_id, "Cannot read from server\n");
          sm_relase();
      }

      set_fd_async(client_socket_fd);

      // printf("write_fault\n");
      // struct sm_ptr *cmd_msg = generate_msg(WRITE_FAULT, addr);
      // protocol_write(client_socket_fd, cmd_msg);
      // free(cmd_msg->ptr);
      // free(cmd_msg);
      // fault_time = 0;
      //

    //exit (0);
}

// functuion receive_message(){
//     struct sm_ptr *msg = protocol_read(client_socket_fd);
//     if (msg){
//       void **cmd_data = parse_msg(msg);
//       char *cmd = (char *)cmd_data[0];
//       struct sm_ptr *data = (struct sm_ptr *)cmd_data[1];
//       if (!strcmp(to releasing ownership, cmd)){
//         if (a has read permission ){
//           mprotect(a, pagesize, PORT_READ);
//         }else if (a has not read permission ){
//           mprotect(a, pagesize, PORT_NONE);
//         }
//         struct sm_ptr *msg = generate_msg(releasing ownership, NULL);
//         protocol_write(client_socket_fd, msg);
//       }
//       else if (!strcmp(giving you read permission, cmd)){
//         mprotect(a, pagesize, PORT_READ);
//         struct sm_ptr *msg = generate_msg(receiving read permission, NULL);
//         protocol_write(client_socket_fd, msg);
//       }
//
//
//       else if (!strcmp(to invalidated, cmd)){
//         mprotect(a, pagesize, PORT_NONE);
//         struct sm_ptr *msg = generate_msg(react to invalidated, NULL);
//         protocol_write(client_socket_fd, msg);
//       }
//       else if (!strcmp(giving you write permission, cmd)){
//         mprotect(a, pagesize, PORT_WRITE);
//         struct sm_ptr *msg = generate_msg(receiving ownership, NULL);
//         protocol_write(client_socket_fd, msg);
//       }
//     }
// }


void *sm_malloc(size_t size)
{
  struct sigaction sa;
  sa.sa_sigaction = handler;
  sa.sa_flags     = SA_SIGINFO;
  sigemptyset (&sa.sa_mask);
  sigaction (SIGSEGV, &sa, NULL);

    char * a;
    a = mmap (0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mprotect(a, size, PROT_NONE);
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

    msg = protocol_read(client_socket_fd);
    if (msg)
    {
        void **cmd_data = parse_msg(msg);
        free(msg->ptr);
        free(msg);

        if (!cmd_data)
        {
            sm_relase();
            exit(EXIT_FAILURE);
        }

        char *cmd = (char *)cmd_data[0];
        struct sm_ptr *data = (struct sm_ptr *)cmd_data[1];

        if (is_confirm_cmd(cmd, CLIENT_CMD_BARRIER))
        {
        }
        free(cmd);
        free(data->ptr);
        free(data);
        free(cmd_data);
    }
    else
    {
        node_printf(host_id, "Cannot read from server\n");
        sm_relase();
    }
    set_fd_async(client_socket_fd);
}

void sm_bcast(void **addr, int root_nid)
{
}
