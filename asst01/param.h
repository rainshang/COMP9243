//
//  param.h
//  param
//
//  Created by 李昂 on 2018/3/13.
//  Copyright © 2018年 李昂. All rights reserved.
//

#ifndef param_h
#define param_h
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <sys/time.h>
#include <string.h>
#include <stropts.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>

#define LOG_PRINT(fmt, args...) sm_log_print("%s(%s:%d)==>" fmt, __FILE__, __FUNCTION__, __LINE__, ##args)

struct Host_name
{
    char host_name[10];
};
typedef struct Host_name Host_name;

//struct Node_option
//{
//    char *option;
//};
//typedef struct Node_option Node_option[100];

struct Parameters
{
    Host_name *host_names;
    char *node_option;
    char *execute_file;
    int client_option_num;
    char *log_file;
    //char *node_option;
    int host_num;
};
typedef struct Parameters Parameters;

Parameters *parse_argv(int, char **);
int sm_log_init(char *log_filename);
void sm_log_print(char *format, ...);
void sm_log_close(char *log_filename);

#endif /* param_h */
