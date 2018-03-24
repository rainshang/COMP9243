#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdbool.h>

#include "comm.h"
#include "sm.h"

#define DEBUG false

#define NUM_ARGS 4

enum internal_args {
    NID = 1,
    NODES,
    HOST,
    PORT
};

static int alloc_socket;
static int node_id;

// Clean up all sm resources
static void sm_cleanup()
{
    // Remove bookkeeping structures here
    close(alloc_socket);
}

// Kill the client program gracefully
static void sm_early_exit()
{
    sm_comm_toggle_async(alloc_socket, false);

    // remove sigint handler
    struct sigaction saio;
    saio.sa_handler = SIG_DFL;
    saio.sa_flags = 0;
    saio.sa_restorer = 0;
    sigemptyset(&saio.sa_mask);
    sigaction(SIGINT, &saio, NULL);

    if (DEBUG)
        fprintf(stderr, "#%d: attempting to exit gracefully\n", node_id);

    sm_cleanup();
    raise(SIGINT);
}

static void sigint_handler()
{
    sm_comm_toggle_async(alloc_socket, false);
    if (DEBUG)
        fprintf(stderr, "#%d: attempting to exit gracefully\n", node_id);
    sm_cleanup();
    raise(SIGINT);
}

static void sm_handle_event(sm_comm_message* message)
{
    switch (message->type) {
    case ALLOC_EXIT:
        if (DEBUG)
            fprintf(stderr, "r%d: exiting early\n", node_id);
        sm_early_exit();
        break;

    case MESSAGE_ERROR:
        if (DEBUG)
            fprintf(stderr, "r%d: message error\n", node_id);
        sm_early_exit();
        break;

    case DISCONNECTED:
        if (DEBUG)
            fprintf(stderr, "r%d: disconnected\n", node_id);
        sm_early_exit();
        break;

    default:
        if (DEBUG)
            fprintf(stderr, "r%d: unexpected event %d\n", node_id, message->type);
        sm_early_exit();
    }
}

static void sm_expect_event(int socket, message_type event)
{
    sm_comm_message message;
    while (sm_comm_receive_message(socket, &message) != event) {
        if (message.type == MESSAGE_ERROR || message.type == INVALID_TYPE)
            sm_early_exit();
        sm_handle_event(&message);
    }
}

static void sm_async_catchIO()
{
    sm_comm_toggle_async(alloc_socket, false);

    sm_comm_message message;
    if (sm_comm_receive_message(alloc_socket, &message))
        sm_handle_event(&message);
    else
        sm_early_exit();

    sm_comm_toggle_async(alloc_socket, true);
}

/* Register a node process with the SM allocator.
 *
 * - Returns 0 upon successful completion; otherwise, -1.
 * - Command arguments have to be passed in; all dsm-related arguments are 
 *   removed, such that only the arguments for the user program remain.
 * - The number of node processes and the node identification of the current
 *   node process are returned in `nodes' and `nid', respectively.
 */
int sm_node_init(int* argc, char** argv[], int* nodes, int* nid)
{
    if (*argc < 1 + NUM_ARGS) {
        fprintf(stderr, "NODE: Insufficient arguments passed to client\n");
        return -1;
    }

    /* Obtain dsm internal args */
    char* host = (*argv)[HOST];
    if (sscanf((*argv)[NID], "%d", nid) != 1) {
        fprintf(stderr, "NODE: Unable to read node id\n");
        return -1;
    }

    if (sscanf((*argv)[NODES], "%d", nodes) != 1) {
        fprintf(stderr, "NODE: Unable to read number of nodes\n");
        return -1;
    }

    unsigned short port;
    if (sscanf((*argv)[PORT], "%hu", &port) != 1) {
        fprintf(stderr, "NODE: Unable to obtain allocator's port\n");
        return -1;
    }

    // Global here for use in debugging messages
    node_id = *nid;

    if (DEBUG) {
        fprintf(stderr,
            "r%d: started sm_node_init, n: %d p: %hu h: %s\n",
            node_id, *nodes, port, host);
    }

    /* Shift args array left by number of internal argumnets */
    for (int i = 1; i < *argc - NUM_ARGS; i++) {
        (*argv)[i] = (*argv)[i + NUM_ARGS];
    }
    *argc -= NUM_ARGS;

    // Obtain address of host
    struct hostent* alloc_hostent = gethostbyname(host);
    if (alloc_hostent == NULL) {
        fprintf(stderr, "r%d: Unable to obtain allocator's internet address\n", *nid);
        return -1;
    }

    // Socket address of allocator
    struct sockaddr_in alloc_sockaddr;
    memset(&alloc_sockaddr, 0, sizeof(alloc_sockaddr));
    alloc_sockaddr.sin_family = AF_INET;
    alloc_sockaddr.sin_port = htons(port);
    alloc_sockaddr.sin_addr = *((struct in_addr*)alloc_hostent->h_addr_list[0]);

    // Create socket to allocator
    alloc_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (alloc_socket < 0) {
        fprintf(stderr, "r%d: failed to create socket\n", *nid);
        return -1;
    }

    // Designate the socket to be kept alive
    int sockopt_bool = 1;
    if (setsockopt(alloc_socket, SOL_SOCKET, SO_KEEPALIVE, &sockopt_bool, sizeof(int))) {
        fprintf(stderr, "r%d: %s\n", *nid, strerror(errno));
        return -1;
    }

    // Connect to the allocator
    if (connect(alloc_socket, (struct sockaddr*)&alloc_sockaddr, sizeof(struct sockaddr_in)) < 0) {
        fprintf(stderr, "r%d: failed to connect to allocator\n", *nid);
        return -1;
    }

    // Send initialisation message
    if (!sm_comm_send_message(alloc_socket, NODE_INIT, (uint32_t)*nid)) {
        fprintf(stderr, "r%d: Header send failed\n", *nid);
        return -1;
    }

    // Block until we receive ALLOC_INIT to continue
    sm_comm_message message;
    while (sm_comm_receive_message(alloc_socket, &message) != ALLOC_INIT) {
        sm_handle_event(&message); // Handle unexpected event
        return -1;
    }

    if (DEBUG)
        fprintf(stderr, "r%d: finished init\n", *nid);

    // Register signal handlers
    struct sigaction saio;

    saio.sa_handler = sigint_handler;
    saio.sa_flags = 0;
    saio.sa_restorer = 0;
    sigemptyset(&saio.sa_mask);
    sigaction(SIGINT, &saio, NULL);

    saio.sa_handler = sm_async_catchIO;
    sigaction(SIGIO, &saio, NULL);

    sm_comm_toggle_async(alloc_socket, true);
    return 0;
}

/* Barrier synchronisation
 *
 * - Barriers are not guaranteed to work after some node processes have quit.
 */
void sm_barrier(void)
{
    sm_comm_toggle_async(alloc_socket, false);

    if (!sm_comm_send_message(alloc_socket, NODE_BARRIER, 0)) {
        fprintf(stderr, "r%d: Error sending barrier message\n", node_id);
        sm_early_exit();
        return;
    }

    if (DEBUG)
        fprintf(stderr, "r%d: At barrier\n", node_id);

    //  Block while handling events until ALLOC_BARRIER received.
    sm_expect_event(alloc_socket, ALLOC_BARRIER);

    if (DEBUG)
        fprintf(stderr, "r%d: barrier complete\n", node_id);

    sm_comm_toggle_async(alloc_socket, true);
}

/* Deregister node process.
 */
void sm_node_exit(void)
{
    sm_comm_toggle_async(alloc_socket, false);

    if (DEBUG)
        fprintf(stderr, "r%d: sending NODE_EXIT\n", node_id);
    // Send exit message
    if (!sm_comm_send_message(alloc_socket, NODE_EXIT, 0)) {
        if (DEBUG)
            fprintf(stderr, "r%d: header send failed\n", node_id);
        sm_cleanup();
    }

    // Wait until ALLOC_EXIT received
    // Allows allocator to fetch resources potentially on the node
    sm_expect_event(alloc_socket, ALLOC_EXIT);

    if (DEBUG)
        fprintf(stderr, "r%d: successfully exited\n", node_id);

    sm_cleanup();
}

/* Allocate object of `size' byte in SM.
 *
 * - Returns NULL if allocation failed.
 */
void* sm_malloc(size_t size)
{
    (void)size;
    return NULL;
}

/* Broadcast an address
 *
 * - The address at `*addr' located in node process `root_nid' is transferred
 *   to the memory area referenced by `addr' on the remaining node processes.
 * - `addr' may not refer to shared memory.
 */
void sm_bcast(void** addr, int root_nid)
{
    (void)addr;
    (void)root_nid;
}
