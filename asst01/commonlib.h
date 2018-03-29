#ifndef _COMMON_LIB_H
#define _COMMON_LIB_H

#include <netdb.h>

typedef char bool;
#define true 1
#define false 0

#define DEBUG true

#define SOCKET_TIMEOUT 10

#define CLIENT_CMD_REGISTER "CLIENT_CMD_REGISTER"
#define CLIENT_CMD_EXIT "CLIENT_CMD_EXIT"
#define SERVER_CMD_EXIT_CLIENTS "SERVER_CMD_EXIT_CLIENTS"
#define CLIENT_CMD_BARRIER "CLIENT_CMD_BARRIER"
#define READ_FAULT "READ_FAULT"
#define CMD_READ_FAULT "CMD_READ_FAULT"

typedef struct sm_ptr
{
    void *ptr; // usually, need to free() this pointer manually
    size_t size;
    bool has_write_permission;
    bool has_read_permission;
} sm_ptr;

/**
 * like perror(const char *), don't call it when no errno is set
 */
void perrorf(const char *format, ...);
int node_printf(int nid, const char *format, ...);
int allocator_printf(const char *format, ...);
/**
 * print sm_ptr as char*
 */
void sm_ptr_print(struct sm_ptr *smptr);
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
int protocol_write(int fd, const struct sm_ptr *msg);
/**
 * will check the O_NONBLOCK flag to read in an infinite loop until getting valid messages or error happening
<<<<<<< HEAD
 *
 * return the message and the msg_size
=======
 * thus, it finally return the data it reads or NULL (error occours)
>>>>>>> a6b21c0f53a2b28fb9efeb3a87568094337d2e67
 */
struct sm_ptr *protocol_read(int fd);
/**
 * from {p_char} to '\0'
 */
unsigned str_len(const char *p_char);
// use the 2 functions to generate/parse message to between allocator/node
struct sm_ptr *generate_msg(const char *cmd, const struct sm_ptr *data);
/**
 * return [char* cmd, sm_ptr* data]
 */
void **parse_msg(const struct sm_ptr *msg);
char *generate_confirm_cmd(const char *cmd);
bool is_confirm_cmd(const char *cmd_to_check, const char *cmd);

#endif /* _COMMON_LIB_H */
