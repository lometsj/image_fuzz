#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include "kcov.h"
#include <stdio.h>
#include <arpa/inet.h>//inet_addr() sockaddr_in
#include <string.h>//bzero()
#include <sys/socket.h>//socket
#include <unistd.h>
#include <stdlib.h>//exit()
#include <sys/epoll.h> //epoll
#include <signal.h>
#include <sys/mount.h>
#include <dirent.h>
#include <string.h>

#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>




#define MAXLINE 8192
#define SERV_PORT 8000

struct kcov *cov_data = NULL;
int cov_len = 0;
int dmesg_fd = 0;
/*
just like syz_fuzzer in syzkaller
receive request from host and execute fuzz data and get coverage data from kcov_fs
*/


int file_ops(char *path)
{
	DIR *dp = NULL;
	struct dirent *st;
	struct stat sta;
	int ret = 0;
	char tmp_name[1024]={0};
	dp = opendir(path);
	if(dp == NULL)
	{
		printf("open dir error!!\n");
		return -1;
	}
	while(1)
	{
		st = readdir(dp);
		if(NULL == st) //读取完毕
		{
			break;
		}
		strcpy(tmp_name, path);
		if(path[strlen(path)-1] != '/') //判断路径名是否带/
			strcat(tmp_name,"/");
		strcat(tmp_name,st->d_name);  //新文件路径名
		ret = stat(tmp_name, &sta); //查看目录下文件属性
		if(ret < 0)
		{
			printf("read stat fail\n");
			return -1;
		}
 
		if(S_ISDIR(sta.st_mode)) //如果为目录文件
		{
			if( 0 == strcmp("..",st->d_name) || 0 == strcmp(".",st->d_name)) //忽略当前目录和上一层目录
				continue;
			else
			{
				file_ops(tmp_name);  //递归读取
			}
		}
		else	//不为目录则打印文件路径名
		{
			// printf("%s\n",tmp_name);
            int fd = open(tmp_name, O_RDWR);
            char buf[100];
            read(fd, buf, 100);
            write(fd, buf, 100);
		}
	}
	closedir(dp);
	return 0;
}

int handle_request(int fd){

    //set timeout
    alarm(10);

    // say hello to host
    // hello tsj
    if(write(fd, "tsj", 4) != 4){
        printf("say hello error\n");
        return -1;
    }

    //read input fuzz data path and check file exist
    char input_path[1024] = {0};
    read(fd, input_path, 1024);
    puts(input_path);
    if(access(input_path, F_OK) != 0){
        printf("input  data not exist\n");
        return -1;
    }

    //enable kcov, do fuzz disable kcov
    //child only do enable and disable,father do collect
    // 1. dd 2. mount 3. file ops abc

    //dd no need kcov
    //mmap or direct write to block device , both ok
    char cmd[1024] = {0};
    snprintf(cmd, 1023, "dd if=%s of=/dev/pmem0", input_path);
    system(cmd);

    kcov_enable(cov_data);

    umount("/mnt/test");
    mount("/dev/pmem0", "/mnt/test", "eulerfs", 0, "");
    file_ops("/mnt/test");
    umount("/mnt/test");
    
    kcov_disable(cov_data);

}

void init(){
    cov_data = kcov_new();
    if(cov_data == NULL){
        puts("init kcov error");
        exit(1);
    }
    dmesg_fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
    if(dmesg_fd<0){
        puts("cannot open dmesg file");
        exit(1);
    }
    lseek(dmesg_fd, 0, SEEK_END);
}


int send_cov_to_host(int fd){
    for(int i=0;i<cov_len;i++){
        write(fd, &cov_data->cover[i], sizeof(unsigned long long));
    }
}

//syzkaller use regular expression,at this time just use strstr for simple impl
int check_is_panic(char *buf){
    char *blacklist[] = {
        "KASAN",
        "BUG",
    };
    int str_len = sizeof(blacklist) / sizeof(unsigned long long);
    for(int i=0;i<str_len;i++){
        char *ret = strstr(buf, blacklist[i]);
        if(ret != NULL)return 1;
    }
    return 0;
}


void check_dmesg(int fd){
    //check dmesg and send goodbye to host
    char *buf_tmp = (char *)malloc(4096*10);
    int read_len = 0;
    while((read_len = read(dmesg_fd, buf_tmp, 4096*10)) > 0){
        buf_tmp[read_len-1]= '\x00';
        puts(buf_tmp);
        if(check_is_panic(buf_tmp) == 1){
            write(fd, "fuck", 4);//got panic,what the fuck?!
            exit(-1);//  exit, let refresh vm
            return;
        }
        
    }
    write(fd, "sad", 4);
}

int set_server(){
    struct sockaddr_in servaddr, cliaddr;
    socklen_t cliaddr_len;
    int listenfd, connfd;
    char buf[MAXLINE];
    char str[INET_ADDRSTRLEN];
    int i, n;
    pid_t pid;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);

    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(SERV_PORT);

    bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    listen(listenfd, 20);

    printf("Accepting connections ...\n");
    while (1) {
        cliaddr_len = sizeof(cliaddr);
        connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &cliaddr_len);
        kcov_reset(cov_data);
        pid = fork();
        if (pid == 0) {
            close(listenfd);
            handle_request(connfd);
            close(connfd);
            return 0;
        } else if (pid > 0) {
            int status;
            // loop to wait child dead, send kcov data at the same time
            while(waitpid(pid, &status, WNOHANG) == 0){
                cov_len = kcov_collect(cov_data);
                if(cov_len > 0){
                    send_cov_to_host(connfd);
                }
            }
            cov_len = kcov_collect(cov_data);
            if(cov_len > 0){
                send_cov_to_host(connfd);
            }
            umount("/mnt/test");
            check_dmesg(connfd);
            close(connfd);
        }  else
            puts("fork");
    }
    return 0;
}




int main(){
    init();
    set_server();
    return 0;
}