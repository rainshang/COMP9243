#ifndef _COMMON_LIB_H
#define _COMMON_LIB_H

#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/time.h>

#define SOCKET_TIMEOUT 10
#define MSG_CONFIRM_SURFIX "_CONFIRM"
#define LEN_MSG_CONFIRM_SURFIX 8
#define CLIENT_MSG_REGISTER "CLIENT_MSG_REGISTER"
#define CLIENT_MSG_EXIT "CLIENT_MSG_EXIT"
#define SERVER_MSG_EXIT_CLIENTS "SERVER_MSG_EXIT_CLIENTS"
#define SERVER_MSG_BARRIER "SERVER_MSG_BARRIER"

typedef int bool;
#define true 1
#define false 0

/**
 * Like perror(const char *), don't call it when no errno is set
 */
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
        perror("Gethostname failed\n");
        exit(EXIT_FAILURE);
    }
    struct in_addr **h_addr_list = (struct in_addr **)gethostbyname(host_name)->h_addr_list;
    return inet_ntoa(*h_addr_list[0]);
}

/**
 * set socket timeout
 */
void set_socket_timeout(int socket_fd, unsigned seconds)
{
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
        perror("Server socket cannot set receive timeout\n");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
        perror("Server socket cannot set send timeout\n");
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
 * protocol is {$length of data}{$data}, in which {$length of data} is an int
 */

int protocol_write(int fd, const char *data)
{
    int len_data = str_len(data);
    uint32_t _len_data = htonl(len_data); // in case of value varies on different machine
    char buf[sizeof(uint32_t) + len_data];
    // write int to first 4 bytes
    buf[0] = (_len_data >> 24) & 0xFF;
    buf[1] = (_len_data >> 16) & 0xFF;
    buf[2] = (_len_data >> 8) & 0xFF;
    buf[3] = _len_data & 0xFF;
    // write the remaining
    memccpy(buf + 4, data, 0, len_data);
    return write(fd, buf, sizeof(buf));
}

int protocol_read_once(int fd, char *buf)
{
    uint32_t len_data;
    int len_len = read(fd, &len_data, sizeof(uint32_t));
    if (len_len > 0) // len_len == sizeof(uint32_t)
    {
        read(fd, buf, len_data);
        buf[len_data] = '\0';
        return len_data;
    }
    return len_len;
}

/**
 * will check the O_NONBLOCK flag to read in an infinite loop until getting valid messages or error happening
 */
int protocol_read(int fd, char *buf)
{
    int flags = fcntl(fd, F_GETFL, 0);
    bool is_fd_block = !(flags & O_NONBLOCK);

    int len;
    while (true)
    {
        len = protocol_read_once(fd, buf);
        if (len > 0)
        {
            return len;
        }
        else if (len == 0)
        {
            if (is_fd_block)
            {
                continue;
            }
            else // error
            {
                return len;
            }
        }
        else
        {
            if (is_fd_block) // error
            {
                return len;
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

/**
 * return a string's length,
 */
int str_len(const char *p_char)
{
    const char *tmp_p_char = p_char;
    int len = 0;
    while (*tmp_p_char++)
    {
        ++len;
    }
    return len;
}

/**
 * All the message sent from client to server MUST call this function to wrap,
 * otherwise server will deny it
 * 
 * remember to free
 */
char *generate_client_msg(int nid, const char *command)
{
    int len_msg = str_len(command) + 2;
    int tmp_nid = nid;
    if (tmp_nid) // > 0
    {
        while (tmp_nid > 0)
        {
            tmp_nid /= 10;
            ++len_msg;
        }
    }
    else
    {
        ++len_msg;
    }

    char *msg = malloc(++len_msg);
    snprintf(msg,
             len_msg,
             "#%d:%s",
             nid,
             command);
    msg[len_msg] = '\0';
    return msg;
}

/**
 * To parse the message sent from client
 * 
 * @param
 *      msg is the string read from socket, e.g. "#1:CLIENT_MSG_EXIT"
 * @param
 *      the nid in msg, will save in this, e.g. 1
 * 
 * success, return command, e.g. "CLIENT_MSG_EXIT"; else NULL
 * 
 * remember to free
 */
char *split_client_msg(const char *msg, int *nid)
{
    char *p_sharp = strchr(msg, '#');
    if (!p_sharp)
    {
        return NULL;
    }
    char *p_colon = strchr(msg, ':');
    if (!p_colon)
    {
        return NULL;
    }
    unsigned s_nid_len = p_colon - p_sharp;
    char s_nid[s_nid_len];
    unsigned i;
    for (i = 0; i < s_nid_len; ++i)
    {
        ++p_sharp;
        s_nid[i] = *p_sharp;
    }
    *nid = atoi(s_nid);

    char *p_command = p_colon;

    unsigned len_conmmand = 0;
    while (*p_command++)
    {
        ++len_conmmand;
    }
    char *command = malloc(len_conmmand);
    p_command = command;
    while (*p_colon++)
    {
        *p_command = *p_colon;
        ++p_command;
    }
    return command;
}

/**
 * generate a confirm(reply) message of one message, {$original_msg}MSG_CONFIRM_SURFIX
 * 
 * remember to free
 */
char *generate_confirm_msg(const char *command)
{
    unsigned len_msg = str_len(command);
    len_msg += LEN_MSG_CONFIRM_SURFIX;
    char *msg = malloc(++len_msg);
    snprintf(msg,
             len_msg,
             "%s%s",
             command,
             MSG_CONFIRM_SURFIX);
    msg[len_msg] = '\0';
    return msg;
}

/**
 * check $msg is the confirm message of $command, {$msg} = {$command}MSG_CONFIRM_SURFIX
 */
bool is_confirm_msg(const char *msg, const char *command)
{
    char *expected_msg = generate_confirm_msg(command);
    bool b = !strcmp(expected_msg, msg);
    free(expected_msg);
    return b;
}

#endif /* _COMMON_LIB_H */