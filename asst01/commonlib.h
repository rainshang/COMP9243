#ifndef _COMMON_LIB_H
#define _COMMON_LIB_H

#include <netdb.h>

typedef char bool;
#define true 1
#define false 0

#define SOCKET_TIMEOUT 10

#define CLIENT_CMD_REGISTER "CLIENT_CMD_REGISTER"
#define CLIENT_CMD_EXIT "CLIENT_CMD_EXIT"
#define SERVER_CMD_EXIT_CLIENTS "SERVER_CMD_EXIT_CLIENTS"
#define SERVER_CMD_BARRIER "SERVER_CMD_BARRIER"

/**
 * Like perror(const char *), don't call it when no errno is set
 */
void perrorf(const char *format, ...);
void set_fd_block(int fd);
void set_fd_nonblock(int fd);
void set_fd_async(int fd);
void set_fd_sync(int fd);
const char *get_localhost_ip();
/**
 * set socket timeout
 */
void set_socket_timeout(int socket_fd, unsigned seconds);
void init_sockaddr_in(struct sockaddr_in *sockaddr, const char *ip, int port);
// use the 2 functions to write/read one message via socket/file/pipe etc.
int protocol_write(int fd, const char *msg, size_t msg_size);
/**
 * will check the O_NONBLOCK flag to read in an infinite loop until getting valid messages or error happening
 * 
 * return the message and the msg_size
 */
char *protocol_read(int fd, size_t *msg_size);
bool check_errno();
/**
 * from {p_char} to '\0'
 */
unsigned str_len(const char *p_char);
// use the 2 functions to generate/parse message to between allocator/node
/**
 * return the message and the msg_size
 */
char *generate_msg(const char *cmd, const char *data, size_t data_size, size_t *msg_size);
/**
 * return [cmd, data] and data_size
 */
char **parse_msg(const char *msg, size_t msg_size, size_t *data_size);
char *generate_confirm_cmd(const char *cmd);
bool is_confirm_cmd(const char *cmd_to_check, const char *cmd);

#endif /* _COMMON_LIB_H */