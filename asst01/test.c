#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>

#include "commonlib.h"

int main()
{
    int _pipe[2];
    if (pipe(_pipe) < 0)
    {
        perror("曹磊？创建pipe失败？\n");
    }

    char *smptr = mmap(NULL, getpagesize() * 0xffff,
                       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                       -1, 0);
    printf("可用共享内存地址:%p\n", smptr);

    smptr = mmap(NULL, getpagesize() * 0xffff,
                 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                 -1, 0);
    printf("可用共享内存地址:%p\n", smptr);
    smptr = mmap(NULL, getpagesize() * 0xffff,
                 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                 -1, 0);
    printf("可用共享内存地址:%p\n", smptr);
    smptr = mmap(NULL, getpagesize() * 0xffff,
                 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                 -1, 0);
    printf("可用共享内存地址:%p\n", smptr);
    smptr = mmap(NULL, getpagesize() * 0xffff,
                 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                 -1, 0);
    printf("可用共享内存地址:%p\n", smptr);

    int host_id = 0;

    struct sm_ptr *data = malloc(sizeof(struct sm_ptr));
    data->size = sizeof(host_id) + sizeof(smptr);
    char *data_ptr = malloc(data->size);
    memcpy(data_ptr, &host_id, sizeof(host_id));
    memcpy(data_ptr + sizeof(host_id), &smptr, sizeof(smptr));
    data->ptr = data_ptr;
    struct sm_ptr *msg = generate_msg(CLIENT_CMD_REGISTER, data);
    free(data->ptr);
    free(data);
    protocol_write(_pipe[1], msg);
    free(msg->ptr);
    free(msg);

    msg = protocol_read(_pipe[0]);
    void **cmd_data = parse_msg(msg);
    free(msg->ptr);
    free(msg);

    char *cmd = (char *)cmd_data[0];
    data = (struct sm_ptr *)cmd_data[1];

    memcpy(&host_id, data->ptr, sizeof(host_id));

    smptr = malloc(sizeof(void *));
    memcpy(&smptr, data->ptr + sizeof(host_id), sizeof(smptr));
    printf("收到共享内存地址:%p\n", smptr);

    free(cmd);
    free(data->ptr);
    free(data);
    free(cmd_data);
}