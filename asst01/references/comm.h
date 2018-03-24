#ifndef _SM_COMM_H
#define _SM_COMM_H

#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

typedef enum _message_type {
    NODE_INIT, /* node sends init to allocator */
    ALLOC_INIT, /* allocator instructs node to return from init */

    NODE_BARRIER, /* node sends barrier to allocator */
    ALLOC_BARRIER, /* allocator instructs node to proceed with barrier */

    NODE_EXIT, /* client sends exit to allocator upon node exit */
    ALLOC_EXIT, /* allocator instructs node to exit */

    DISCONNECTED,
    MESSAGE_ERROR,
    INVALID_TYPE
} message_type;

// CASPIAN: We'll need to cast the enum value to u_int8_t, otherwise it is an unsigned long.
typedef struct _message_header_internal {
    u_int32_t argument;
    u_int8_t type;
} sm_comm_message_header_internal;

typedef struct _message_header {
    u_int32_t argument;
    message_type type;
} sm_comm_message;

bool sm_comm_toggle_async(int socket, bool async);

ssize_t sm_comm_send_all(int socket, void* buffer, size_t buflen);
ssize_t recv_all(int socket, void* buffer, size_t buflen);

message_type sm_comm_receive_message(int socket, sm_comm_message* message);
bool sm_comm_send_message(int socket, message_type type, u_int32_t argument);

#endif
