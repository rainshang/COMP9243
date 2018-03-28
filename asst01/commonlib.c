#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/time.h>

#include "commonlib.h"

static const char *CMD_DATA_DELIMITER = "$";
static const unsigned LEN_CMD_DATA_DELIMITER = 1;
static const char *CMD_CONFIRM_SURFIX = "_CONFIRM";
static const unsigned LEN_CMD_CONFIRM_SURFIX = 8;

void perrorf(const char *format, ...)
{
    va_list arg_list;
    va_start(arg_list, format);
    vfprintf(stderr, format, arg_list);
    va_end(arg_list);
    perror("");
}

int node_printf(int nid, const char *format, ...)
{
    printf("#%d:", nid);
    va_list arg_list;
    va_start(arg_list, format);
    vprintf(format, arg_list);
    va_end(arg_list);
}
int allocator_printf(const char *format, ...)
{
    printf(":");
    va_list arg_list;
    va_start(arg_list, format);
    vprintf(format, arg_list);
    va_end(arg_list);
}
void sm_ptr_print(struct sm_ptr *smptr)
{
    unsigned i;
    char *p = (char *)smptr->ptr;
    for (i = 0; i < smptr->size; ++i)
    {
        printf("%c", p[i]);
    }
}

void set_fd_block(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

void set_fd_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void set_fd_async(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETOWN, getpid());
    fcntl(fd, F_SETFL, flags | O_ASYNC);
}

void set_fd_sync(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETOWN, getpid());
    fcntl(fd, F_SETFL, flags & ~O_ASYNC);
}

const char *get_localhost_ip()
{
    char host_name[NI_MAXSERV];
    if (gethostname(host_name, sizeof(host_name)) == -1)
    {
        perror("get_localhost_ip: cannot gethostname\n");
        exit(EXIT_FAILURE);
    }
    struct in_addr **h_addr_list = (struct in_addr **)gethostbyname(host_name)->h_addr_list;
    return inet_ntoa(*h_addr_list[0]);
}

void set_socket_timeout(int socket_fd, unsigned seconds)
{
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
        perror("set_socket_timeout: cannot set receive timeout\n");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
        perror("set_socket_timeout: cannot set send timeout\n");
        exit(EXIT_FAILURE);
    }
}

void init_sockaddr_in(struct sockaddr_in *sockaddr, const char *ip, int port)
{
    memset(sockaddr, 0, sizeof(*sockaddr));
    (*sockaddr).sin_family = AF_INET;
    (*sockaddr).sin_addr.s_addr = ip ? inet_addr(ip) : htonl(INADDR_ANY);
    (*sockaddr).sin_port = htons(port);
}

/**
 * protocol is {msg->size}{msg->ptr}, in which {msg->size} is an int
 */
int protocol_write(int fd, const struct sm_ptr *msg)
{
    uint32_t _msg_size = htonl(msg->size); // in case of value varies on different machine
    char buf[4 + msg->size];
    // write int to first 4 bytes
    buf[0] = (_msg_size >> 24) & 0xFF;
    buf[1] = (_msg_size >> 16) & 0xFF;
    buf[2] = (_msg_size >> 8) & 0xFF;
    buf[3] = _msg_size & 0xFF;
    // write the remaining
    memcpy(buf + 4, msg->ptr, msg->size);
    return write(fd, buf, sizeof(buf));
}

// to read the header, which is the size of coming msg
static int protocol_read_step_one(int fd)
{
    uint32_t _msg_size;
    int len = read(fd, &_msg_size, 4);
    if (len > 0) // len == sizeof(uint32_t) == 4
    {
        return _msg_size;
    }
    return len; // didn't read
}

// after read a valid size, then read that size of msg
static struct sm_ptr *protocol_read_step_two(int fd, size_t msg_size)
{
    char *msg_ptr = malloc(msg_size);
    int len = read(fd, msg_ptr, msg_size);

    struct sm_ptr *msg;

    if (len > 0)
    {
        msg = malloc(sizeof(struct sm_ptr));
        msg->ptr = msg_ptr;
        msg->size = msg_size;
        return msg;
    }
    else
    {
        free(msg_ptr);
        fprintf(stderr, "protocol_read_step_two: read msg error\n");
        exit(EXIT_FAILURE);
    }
}

struct sm_ptr *protocol_read(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    bool is_fd_block = !(flags & O_NONBLOCK);

    int len;
    while (true)
    {
        len = protocol_read_step_one(fd);
        if (len > 0)
        {
            return protocol_read_step_two(fd, len);
        }
        else if (len == 0)
        {
            if (is_fd_block)
            {
                continue;
            }
            else // error
            {
                return NULL;
            }
        }
        else
        {
            if (is_fd_block) // error
            {
                return NULL;
            }
            else
            {
                if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)
                {
                    continue;
                }
                else
                {
                    return NULL;
                }
            }
        }
    }
}

unsigned str_len(const char *p_char)
{
    const char *tmp_p_char = p_char;
    unsigned len = 0;
    while (*tmp_p_char++)
    {
        ++len;
    }
    return len;
}

// {cmd}${data->ptr}
struct sm_ptr *generate_msg(const char *cmd, const struct sm_ptr *data)
{
    unsigned len_cmd = str_len(cmd);
    struct sm_ptr *msg = malloc(sizeof(struct sm_ptr));
    msg->size = len_cmd + LEN_CMD_DATA_DELIMITER + (data ? data->size : 0);
    msg->ptr = malloc(msg->size);

    memcpy(msg->ptr, cmd, len_cmd);
    memcpy(msg->ptr + len_cmd, CMD_DATA_DELIMITER, LEN_CMD_DATA_DELIMITER);
    if (data)
    {
        memcpy(msg->ptr + len_cmd + LEN_CMD_DATA_DELIMITER, data->ptr, data->size);
    }

    return msg;
}

void **parse_msg(const struct sm_ptr *msg)
{
    char *ptr_delimiter = strstr(msg->ptr, CMD_DATA_DELIMITER);
    if (!ptr_delimiter)
    {
        return NULL;
    }
    void **cmd_data = malloc(sizeof(char *) + sizeof(struct sm_ptr));

    unsigned len_cmd = ptr_delimiter - (char *)msg->ptr;
    char *cmd = malloc(len_cmd + 1);
    cmd_data[0] = cmd;
    memcpy(cmd, msg->ptr, len_cmd);
    cmd[len_cmd] = '\0';

    struct sm_ptr *data = malloc(sizeof(struct sm_ptr));
    cmd_data[1] = data;
    data->size = msg->size - len_cmd - LEN_CMD_DATA_DELIMITER;
    data->ptr = malloc(data->size);
    ptr_delimiter += LEN_CMD_DATA_DELIMITER;
    memcpy(data->ptr, ptr_delimiter, data->size);

    return cmd_data;
}

/**
 * generate a confirm(reply) cmd of one cmd, {$original_cmd}MSG_CONFIRM_SURFIX
 * 
 * remember to free
 */
char *generate_confirm_cmd(const char *cmd)
{
    unsigned len_cmd = str_len(cmd);
    unsigned len_confirm_cmd = len_cmd + LEN_CMD_CONFIRM_SURFIX;
    char *confirm_cmd = malloc(len_confirm_cmd + 1);
    memcpy(confirm_cmd, cmd, len_cmd);
    memcpy(confirm_cmd + len_cmd, CMD_CONFIRM_SURFIX, LEN_CMD_CONFIRM_SURFIX);
    confirm_cmd[len_confirm_cmd] = '\0';
    return confirm_cmd;
}

/**
 * check {cmd_to_check} is the confirm message of {cmd}, {cmd_to_check} = {cmd}MSG_CONFIRM_SURFIX
 */
bool is_confirm_cmd(const char *cmd_to_check, const char *cmd)
{
    char *expected_msg = generate_confirm_cmd(cmd);
    bool b = !strcmp(expected_msg, cmd_to_check);
    free(expected_msg);
    return b;
}