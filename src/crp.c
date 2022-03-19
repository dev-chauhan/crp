#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    if(argc != 4)
    {
        printf("Usage: %s <command> <pid> <name>\n", argv[0]);
        return -1;
    }
    char *command = argv[1];
    int pid = atoi(argv[2]);
    char *name = argv[3];

    int fd;
    if((fd = open("/dev/crp", O_RDWR)) < 0)
    {
        printf("Error: open /dev/crp failed\n");
        return -1;
    }
    if(strcmp(command, "checkpoint") == 0)
    {
        unsigned long args[2] = {0, pid};
        if(read(fd, args, sizeof(args)) < 0)
        {
            printf("Error: read /dev/crp failed\n");
            return -1;
        }
    }else if(strcmp(command, "restore") == 0)
    {
        unsigned long args[2] = {1, pid};
        if(write(fd, args, sizeof(args)) < 0)
        {
            printf("Error: write /dev/crp failed\n");
            return -1;
        }
    }else{
        printf("Error: command %s is not supported\n", command);
        return -1;
    }
    return 0;
}