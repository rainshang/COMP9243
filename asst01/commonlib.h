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

#define SOCKET_TIMEOUT 10
#define CLIENT_MSG_REGISTER "CLIENT_MSG_REGISTER"
#define CLIENT_MSG_EXIT "CLIENT_MSG_EXIT"
#define SERVER_MSG_EXIT_CLIENTS "SERVER_MSG_EXIT_CLIENTS"
#define SERVER_MSG_BARRIER "SERVER_MSG_BARRIER"
#define SERVER_MSG_UNBARRIER "SERVER_MSG_UNBARRIER"

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

void set_fd_unblock(int fd)
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

int protocol_read(int fd, char *buf)
{
    uint32_t len_data;
    int len_len = read(fd, &len_data, sizeof(uint32_t));
    if (len_len > 0) // len == sizeof(uint32_t)
    {
        read(fd, buf, len_data);
        buf[len_data] = '\0';
        return len_data;
    }
    return len_len; // does not match protocol, invalid msg
}

int check_errno()
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
 */
const char *generate_client_msg(int nid, const char *command)
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
 */
const char *split_client_msg(const char *msg, int *nid)
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