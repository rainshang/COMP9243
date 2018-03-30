
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>

#include "sm.h"
#include "commonlib.h"
#include "vec.h"

static int host_id;
static int client_socket_fd;
static int fault_time;

static vec_void_t sm_addr_vector; // to store all the addresses in sm

static void sm_relase()
{
    close(client_socket_fd);
    unsigned i;
    for (i = 0; i < sm_addr_vector.length; ++i)
    {
        struct sm_ptr *tmp = (struct sm_ptr *)sm_addr_vector.data[i];
        free(tmp);
    }
    vec_deinit(&sm_addr_vector);
}

static void sm_sigint_handler()
{
    sm_relase();
}

static void sm_sigpoll_handler()
{
    int len;
    struct sm_ptr *msg = protocol_read(client_socket_fd, &len);

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

static int register_node(void **native_sm_addr, void **aligned_sm_addr)
{
    int pagesize = getpagesize();
    unsigned sm_total_size = pagesize * PAGE_NUM;
    // let system allocate the available shared free memonry
    *native_sm_addr = mmap(NULL, sm_total_size,
                           PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                           -1, 0);
    // if (DEBUG)
    // {
    //     node_printf(host_id, "available sm_address on this node is %p\n", *native_sm_addr);
    // }
    struct sm_ptr *data = malloc(sizeof(struct sm_ptr));
    data->size = sizeof(host_id) + sizeof(pagesize) + sizeof(native_sm_addr);
    char *data_ptr = malloc(data->size);
    memcpy(data_ptr, &host_id, sizeof(host_id));
    memcpy(data_ptr + sizeof(host_id), &pagesize, sizeof(pagesize));
    memcpy(data_ptr + sizeof(host_id) + sizeof(pagesize), native_sm_addr, sizeof(*native_sm_addr));
    data->ptr = data_ptr; // data: {host_id}{pagesize}{sm_addr}
    struct sm_ptr *msg = generate_msg(CLIENT_CMD_REGISTER, data);
    free(data->ptr);
    free(data);
    protocol_write(client_socket_fd, msg);
    free(msg->ptr);
    free(msg);

    int len;
    msg = protocol_read(client_socket_fd, &len);

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
        memcpy(aligned_sm_addr, data->ptr, data->size);
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
    // if (DEBUG)
    // {
    //     node_printf(host_id, "first aligned available sm_address is %p\n", *aligned_sm_addr);
    // }
    return 0;
}

static int align_smaddr(void *native_sm_addr, void **aligned_sm_addr)
{
    int pagesize = getpagesize();
    unsigned sm_total_size = pagesize * PAGE_NUM;
    munmap(native_sm_addr, sm_total_size); // free the first try
    *aligned_sm_addr = mmap(*aligned_sm_addr, sm_total_size,
                            PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                            -1, 0);
    if (MAP_FAILED == *aligned_sm_addr)
    {
        perror("Cannot mmap the entire shared memeory");
        sm_relase();
        return -1;
    }

    struct sm_ptr *data = malloc(sizeof(struct sm_ptr));
    data->size = sizeof(*aligned_sm_addr);
    char *data_ptr = malloc(data->size);
    memcpy(data_ptr, aligned_sm_addr, sizeof(*aligned_sm_addr));
    data->ptr = data_ptr; // data: {aligned_sm_addr}
    struct sm_ptr *msg = generate_msg(CLIENT_CMD_ALIGN, data);
    free(data->ptr);
    free(data);
    protocol_write(client_socket_fd, msg);
    free(msg->ptr);
    free(msg);

    int len;
    msg = protocol_read(client_socket_fd, &len);

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
        munmap(*aligned_sm_addr, sm_total_size); // free the second try
        sm_relase();
        return -1;
    }
    return 0;
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
      //node_printf(host_id, "%p\n", addr);
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

      int len;
      msg = protocol_read(client_socket_fd, &len);
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
            mprotect (addr, 4096, PROT_WRITE|PROT_READ);
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

int sm_node_init(int *argc, char **argv[], int *nodes, int *nid)
{
    // parse arguments
    if (parse_param_and_connect(argc, argv, nodes, nid))
    {
        return -1;
    }

    // register to server with nid and available shared memeory address on this node
    void *native_sm_addr, *aligned_sm_addr;
    if (register_node(&native_sm_addr, &aligned_sm_addr))
    {
        return -1;
    }
    // re-mmap() the aligned sm_addr, system will aligns it slightly by page_size, then double check with allocator that all the nodes are same
    if (align_smaddr(native_sm_addr, &aligned_sm_addr))
    {
        return -1;
    }
    // finally, we got a universal aligned sm_addr
    vec_init(&sm_addr_vector);

    struct sigaction sa;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    sa.sa_handler = sm_sigpoll_handler;
    sigaction(SIGPOLL, &sa, NULL);

    sa.sa_handler = sm_sigint_handler;
    sigaction(SIGINT, &sa, NULL);

    set_fd_async(client_socket_fd);


    struct sigaction saa;
    saa.sa_sigaction = handler;
    saa.sa_flags     = SA_SIGINFO;
    sigemptyset (&saa.sa_mask);
    sigaction (SIGSEGV, &saa, NULL);

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

void *sm_malloc(size_t size)
{

    set_fd_sync(client_socket_fd);

    struct sm_ptr *data = malloc(sizeof(struct sm_ptr));
    data->size = sizeof(size);
    char *data_ptr = malloc(data->size);
    memcpy(data_ptr, &size, sizeof(size));
    data->ptr = data_ptr; // data: {size}
    struct sm_ptr *msg = generate_msg(CLIENT_CMD_MALLOC, data);
    free(data->ptr);
    free(data);
    protocol_write(client_socket_fd, msg);
    free(msg->ptr);
    free(msg);

    int len;
    msg = protocol_read(client_socket_fd, &len);

    if (!msg)
    {
        node_printf(host_id, "Cannot read from allocator\n");
        sm_relase();
        exit(EXIT_FAILURE);
    }

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
    data = (struct sm_ptr *)cmd_data[1];

    bool is_ccmd = is_confirm_cmd(cmd, CLIENT_CMD_MALLOC);
    void *allocated_ptr;
    if (is_ccmd)
    {
        memcpy(&allocated_ptr, data->ptr, data->size);
    }
    free(cmd);
    free(data->ptr);
    free(data);
    free(cmd_data);
    if (!is_ccmd)
    {
        node_printf(host_id, "Unexpected command received.\n");
        sm_relase();
        exit(EXIT_FAILURE);
    }
    if (!allocated_ptr) //0, allocator cannot allocate
    {
        node_printf(host_id, "Cannot sm_malloc %d bytes memory\n", size);
        return NULL;
    }

    struct sm_ptr *smptr = malloc(sizeof(struct sm_ptr));
    smptr->ptr = allocated_ptr;
    smptr->size = size;
    smptr->has_write_permission = true;
    smptr->has_read_permission = true;

    if (mprotect(allocated_ptr, size, PROT_WRITE|PROT_READ))
    {
        node_printf(host_id, "Cannot set %p protect status\n", allocated_ptr);
        sm_relase();
        exit(EXIT_FAILURE);
    }
    vec_push(&sm_addr_vector, smptr);
    set_fd_async(client_socket_fd);
    return allocated_ptr;
}

void sm_barrier(void)
{
    set_fd_sync(client_socket_fd);
    struct sm_ptr *msg = generate_msg(CLIENT_CMD_BARRIER, NULL);
    protocol_write(client_socket_fd, msg);
    free(msg->ptr);
    free(msg);

    int len;
    msg = protocol_read(client_socket_fd, &len);
    if (!msg)
    {
        node_printf(host_id, "Cannot read from allocator\n");
        sm_relase();
        exit(EXIT_FAILURE);
    }
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

    if (is_confirm_cmd(cmd, CLIENT_CMD_BARRIER))
    {
    }
    free(cmd);
    free(data->ptr);
    free(data);
    free(cmd_data);
    set_fd_async(client_socket_fd);
}

void sm_bcast(void **addr, int root_nid)
{
  set_fd_sync(client_socket_fd);









  set_fd_async(client_socket_fd);
}
