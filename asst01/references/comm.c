#include "comm.h"

bool sm_comm_toggle_async(int socket, bool async)
{
    // Get flags on socket
    int flags = fcntl(socket, F_GETFL, 0);
    if (flags < 0)
        return false;

    if (fcntl(socket, F_SETOWN, getpid()) < 0) {
        fprintf(stderr, "Failed to set socket owner\n");
        return false;
    }

    // Toggle the async flag
    flags = !async ? (flags & ~O_ASYNC) : (flags | O_ASYNC);
    return (fcntl(socket, F_SETFL, flags) < 0);
}

/* this function is fully re-entrant as long as all errno is always
 * saved and restored by signal handlers */
// Expect 0 on successful send
ssize_t sm_comm_send_all(int socket, void* buffer, size_t buflen)
{
    int errsv = errno;
    char* ptr = (char*)buffer;

    fd_set send_set;

    // Set a timeout for the select
    struct timeval timeout;
    timeout.tv_sec = 5; /* 5 secs */
    timeout.tv_usec = 0; /* 0 microsecs */

    while (buflen > 0) {
        FD_ZERO(&send_set);
        FD_SET(socket, &send_set);

        // Wait for send, fail on timeout
        if (select(socket + 1, NULL, &send_set, NULL, &timeout) == 0) {
            char* errmsg = "timeout in sm_comm_send_all\n";
            write(STDERR_FILENO, errmsg, strlen(errmsg));
            return -1;
        }

        int ret = send(socket, ptr, buflen, 0);
        if (ret == -1 && errno != EINTR) {
            char* errmsg = "sm_comm_send_all failed\n";
            write(STDERR_FILENO, errmsg, strlen(errmsg));
            return -1;
        }
        ptr += ret;
        buflen -= ret;
    }

    errno = errsv;
    return (ssize_t)buflen;
}

// Expect 0 on successful receive, -1 on failure
ssize_t recv_all(int socket, void* buffer, size_t buflen)
{
    int errsv = errno;
    char* ptr = (char*)buffer;
    fd_set read_set;

    // Set a timeout for the select
    struct timeval timeout;
    timeout.tv_sec = 5; /* 5 secs */
    timeout.tv_usec = 0; /* 0 microsecs */
    while (buflen > 0) {
        FD_SET(socket, &read_set);
        // Wait for input, fail on timeout
        if (select(socket + 1, &read_set, NULL, NULL, &timeout) == 0)
            return -1;

        int ret = recv(socket, ptr, buflen, 0);
        if (ret < 0 || (ret == 0 && buflen > 0))
            return -1;

        ptr += ret;
        buflen -= ret;
    }
    errno = errsv;
    return (ssize_t)buflen;
}

/* Create a network consistent header */
static bool create_header(sm_comm_message* message, message_type type, u_int32_t argument)
{
    if (message == NULL || type < NODE_INIT || type > INVALID_TYPE)
        return false;

    message->type = (uint8_t)type;
    message->argument = htonl(argument);
    return true;
}

/* Wrapper for sending a header over socket */
bool sm_comm_send_message(int socket, message_type type, u_int32_t argument)
{
    sm_comm_message message;
    if (!create_header(&message, type, argument)) {
        fprintf(stderr, "failed to construct header\n");
        return false;
    }

    sm_comm_message_header_internal outgoing;
    outgoing.type = message.type;
    outgoing.argument = message.argument;

    ssize_t nbytes = sm_comm_send_all(socket, (void*)&outgoing, sizeof(outgoing));
    return nbytes == 0;
}

/* Receive and demarshall a message */
message_type sm_comm_receive_message(int socket, sm_comm_message* message)
{
    sm_comm_message_header_internal incoming;
    int err = recv_all(socket, &incoming, sizeof(incoming));
    if (err != 0) {
        message_type error_message = err == -1 && errno == EBADF ? DISCONNECTED : MESSAGE_ERROR;
        message->type = error_message;
        return error_message;
    }

    message->type = (message_type)incoming.type;
    message->argument = ntohl(incoming.argument);

    if (message->type < NODE_INIT || message->type > INVALID_TYPE) {
        message->type = INVALID_TYPE;
        return INVALID_TYPE;
    }

    return message->type;
}
