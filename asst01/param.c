//
//  param.c
//  param
//
//  Created by 李昂 on 2018/3/13.
//  Copyright © 2018年 李昂. All rights reserved.
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "param.h"


void show_usage(){

    char *str = "Usage: dsm [OPTION]... EXECUTABLE-FILE NODE-OPTION...\n\
    -H HOSTFILE list of host names\n\
    -h          this usage message\n\
    -l LOGFILE  log each significant allocator action to LOGFILE\n\
    (e.g., read/write fault, invalidate request)\n\
    -n N        fork N node processes\n\
    -v          print version information\n\
    \n\
    Starts the allocator, which forks N copies (one copy if -n not given) of\n\
    EXECUTABLE-FILE.  The NODE-OPTIONs are passed as arguments to the node\n\
    processes.  The hosts on which node processes are started are given in\n\
    HOSTFILE, which defaults to `hosts'.  If the file does not exist,\n\
    'localhost' is used.";

    printf("%s\n", str);
    exit(0);
    return;

}

void parameters_init(Parameters *parameters)
{

    parameters->host_names = NULL;
    parameters->host_num = 1;
    parameters->execute_file = NULL;
    parameters->log_file = NULL;
    parameters->client_option_num = 0;
    //parameters->log_file = NULL;
    //    char* temp = malloc(sizeof(char)*10);
    //    parameters->node_option = temp;
    char* temp = malloc(sizeof(char) * 1000);
    if (temp == NULL) {
        printf("Error: Cannot allocate memory.\n");
        exit(-1);
    }
    //char* temp1 = malloc(sizeof(char) * 1000);

    parameters->node_option = temp;
}

int extract_host_names(char *file_name, Parameters *parameters)
{
    FILE *fp;

    int c = 0; //c为文件当前字符
    int t = 0;
    int line = 0; //行数统计

    fp = fopen(file_name, "r");
    if (fp == NULL)
    {
        //        for (i = 0;i < parameters->host_num;i ++) {
        //            printf("%s\n", temp->host_name);
        //            temp ++;
        //        }

        return 1;
    }

    while ((c = fgetc(fp)) != EOF) //逐个读入字符直到文件结尾
    {
        if (c == '\n' && !t)
        {
            continue;
        }
        else if (c == '\n' && t)
        {
            t = 0;
            line++;
        }
        else
        {
            t = 1;
        }
    }

    Host_name *temp = malloc(sizeof(Host_name) * parameters->host_num);

    parameters->host_names = temp;

    int i = 0;
    temp = parameters->host_names;
    for (i = 0; i < parameters->host_num; i++)
    {
        snprintf(temp->host_name, 10, "localhost");
        temp++;
    }

    temp = parameters->host_names;

    for (i = 0; i < parameters->host_num; i++)
    {
        if (fscanf(fp, "%s\n", temp->host_name) == EOF)
        {
            rewind(fp);
            if (fscanf(fp, "%s\n", temp->host_name) == EOF)
                break;
        }
        temp++;
    }

    fclose(fp);
    return 0;
}

Parameters *parse_argv(int argc, char **argv)
{
    int index;
    int c;

    char *host_name_file = NULL;

    opterr = 0;
    Parameters *parameters = malloc(sizeof(Parameters));

    parameters_init(parameters);

    while ((c = getopt(argc, argv, "Nn:H:l:h:")) != -1)
        switch (c)
    {
        case 'H':
            host_name_file = optarg;
            break;

        case 'n':
        case 'N':
            parameters->host_num = atoi(optarg);
            break;

        case 'l':
            parameters->log_file = optarg;
            break;

        case 'h':
            show_usage();
            break;
        case 'v':
            printf("version ......");
            break;
    }

    index = optind;

    parameters->execute_file = argv[index];

    if (parameters->execute_file == NULL)
    {
        printf("'EXECUTABLE-FILE' is not given.\n");
        return (void *)0;
    }

    index++;
    if (index < argc)
    {
        //parameters->node_option = malloc(sizeof(char));
        //        if (parameters->node_option == NULL){
        //            printf("error.....");
        //        }
        int count = 0;
        for (index = index; index < argc; index++) {
            int i;
            int size = strlen(argv[index]);
            for (i = 0;i < size;i ++) {
                parameters->node_option[count++] = argv[index][i];
            }
            parameters->node_option[count++] = ' ';

        }
    }
    //printf("======%s\n", parameters->node_option);

    extract_host_names(host_name_file, parameters);

    return parameters;
}
//log file


static FILE* fpp;

int sm_log_init(char* log_filename)
{


   if (strlen(log_filename) == 0)
   {
       fpp = NULL;
       return 0;
   }

   fpp = fopen(log_filename, "a+");
   if (fpp == NULL)
   {
       printf ("open log %s error: %d, %s\n", log_filename, errno, strerror(errno));
       return -1;
   }


   return 0;
}

void sm_log_close(char* log_filename)
{

        fclose(fpp);
        //fpp = NULL;


}

// static char *format_time(const time_t * mytime)
// {
//    static char s[50];
//    struct tm curr = *localtime(mytime);

//    if(curr.tm_year > 50)
//    {
//        snprintf(s, sizeof(s) - 1, "%04d-%02d-%02d %02d:%02d:%02d", curr.tm_year + 1900, curr.tm_mon + 1, curr.tm_mday, curr.tm_hour, curr.tm_min, curr.tm_sec);
//    }
//    else
//    {
//        snprintf(s, sizeof(s) - 1, "%04d-%02d-%02d %02d:%02d:%02d", curr.tm_year + 2000, curr.tm_mon + 1, curr.tm_mday, curr.tm_hour, curr.tm_min, curr.tm_sec);
//    }
//    return s;
// }
void sm_log_print(char *format, ...)
{

   va_list ap;
   //struct timeval tv;

   va_start(ap,format);
   //gettimeofday(&tv, NULL);
   //fprintf(fpp, "[%s.%.6d] ", format_time((const time_t *) &(tv.tv_sec)), (int) tv.tv_usec);
   vfprintf(fpp, format, ap);
   fprintf(fpp, "\n");
   va_end(ap);
   //fflush(fpp);
   return;

}
