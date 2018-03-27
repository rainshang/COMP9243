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
 * protocol is {length of msg}{msg}, in which {length of msg} is an int
 */
int protocol_write(int fd, const char *msg, size_t msg_size)
{
    uint32_t _msg_size = htonl(msg_size); // in case of value varies on different machine
    char buf[4 + msg_size];
    // write int to first 4 bytes
    buf[0] = (_msg_size >> 24) & 0xFF;
    buf[1] = (_msg_size >> 16) & 0xFF;
    buf[2] = (_msg_size >> 8) & 0xFF;
    buf[3] = _msg_size & 0xFF;
    // write the remaining
    memcpy(buf + 4, msg, msg_size);
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
static char *protocol_read_step_two(int fd, size_t msg_size)
{
    char *msg = malloc(msg_size);
    int len = read(fd, msg, msg_size);

    if (len > 0)
    {
        return msg;
    }
    else
    {
        free(msg);
        fprintf(stderr, "protocol_read_step_two: read msg error\n");
        exit(EXIT_FAILURE);
    }
}

char *protocol_read(int fd, size_t *msg_size)
{
    int flags = fcntl(fd, F_GETFL, 0);
    bool is_fd_block = !(flags & O_NONBLOCK);

    int len;
    while (true)
    {
        len = protocol_read_step_one(fd);
        if (len > 0)
        {
            *msg_size = len;
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
                *msg_size = len;
                return NULL;
            }
        }
        else
        {
            if (is_fd_block) // error
            {
                *msg_size = len;
                return NULL;
            }
            else
            {
                continue;
            }
        }
    }
}

bool check_errno()
{
    return errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN;
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

// {cmd}${data}
char *generate_msg(const char *cmd, const char *data, size_t data_size, size_t *msg_size)
{
    unsigned len_cmd = str_len(cmd);
    *msg_size = len_cmd + LEN_CMD_DATA_DELIMITER + data_size;
    char *msg = malloc(*msg_size);

    memcpy(msg, cmd, len_cmd);
    memcpy(msg + len_cmd, CMD_DATA_DELIMITER, LEN_CMD_DATA_DELIMITER);
    memcpy(msg + len_cmd + LEN_CMD_DATA_DELIMITER, data, data_size);

    return msg;
}

char **parse_msg(const char *msg, size_t msg_size, size_t *data_size)
{
    char *ptr_delimiter = strstr(msg, CMD_DATA_DELIMITER);
    if (!ptr_delimiter)
    {
        return NULL;
    }
    char **cmd_data = malloc(sizeof(char *) * 2);

    unsigned len_cmd = ptr_delimiter - msg;
    cmd_data[0] = malloc(len_cmd+1);
    memcpy(cmd_data[0], msg, len_cmd);
    cmd_data[0][len_cmd] = '\0';

    *data_size = msg_size - len_cmd - LEN_CMD_DATA_DELIMITER;
    cmd_data[1] = malloc(*data_size);
    ptr_delimiter += LEN_CMD_DATA_DELIMITER;
    memcpy(cmd_data[1], ptr_delimiter, *data_size);

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
    char *confirm_cmd = malloc(len_confirm_cmd);
    memcpy(confirm_cmd, cmd, len_cmd);
    memcpy(confirm_cmd + len_cmd, CMD_CONFIRM_SURFIX, LEN_CMD_CONFIRM_SURFIX);
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