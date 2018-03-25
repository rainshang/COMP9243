#include <stdio.h>

#include "sm.h"

void fatal(int nid, char *msg)
{
    printf("node %d: Fatal internal error:\n%s\n", nid, msg);
    exit(1);
}

/**
 * argv:{$exe, $server_ip, $server_port, $host_count, $host_id}
 */
int main(int argc, char *argv[])
{
    int host_count;
    int host_id;

    // sscanf(argv[4], "%d", &host_id);
    // if (host_id != 10001) // mock accept() timeout
    // {
    if (sm_node_init(&argc, &argv, &host_count, &host_id))
    {
        fatal(host_id, "share: Cannot initialise!");
    }
    // }

    // if(host_id == 10001){
    //     sleep(5);
    //     return;
    // }

    sm_barrier();
    sm_node_exit();
}