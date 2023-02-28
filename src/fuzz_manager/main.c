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
#include "vix.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <libgen.h>
#include "common.h"



//hardcoding  something
#define DEST_SCP "tsj@192.168.51.128:~"
#define SNAPSHOT_NAME "fuzz_init2"


#define MAP_SIZE_POW2 16
#define MAP_SIZE (1<<MAP_SIZE_POW2)
uint8_t __afl_area_initial[MAP_SIZE];
uint8_t *__afl_area_ptr = __afl_area_initial;

static unsigned char *afl_area_ptr = 0;
static unsigned int afl_inst_rms = MAP_SIZE;

#define SHM_ENV_VAR "__AFL_SHM_ID"
#define FORKSRV_FD 198

int fd;
pid_t child_pid;
uint8_t child_time_out;



void init_shm(){
    char *id_str = getenv(SHM_ENV_VAR);
    if(id_str){
        uint32_t shm_id = atoi(id_str);
        __afl_area_ptr = shmat(shm_id, NULL, 0);
        if(__afl_area_ptr == (void *)-1) _exit(1);
        __afl_area_ptr[0] = 1;
    }
}

static void afl_forkserver(const char *out_file){
    static uint8_t tmp[4];
    pid_t child_pid = 1234;
    
    if(write(FORKSRV_FD+1, "tsj", 4) == 4){
        while(1){
            uint32_t was_killed;
            int status;
            if(read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);
            child_pid = fork();
            if(child_pid < 0) _exit(1);
            if(!child_pid){
                close(FORKSRV_FD);
                close(FORKSRV_FD+1);
                return;
            }
            if(write(FORKSRV_FD+1, &child_pid, 4) != 4) _exit(1);
            if(waitpid(child_pid, &status, 0) < 0) _exit(1);
            
            // if(waitpid(child_pid, &status, 0) < 0) _exit(1);
            if(write(FORKSRV_FD+1, &status, 4) != 4) _exit(1);
        }
    }
    else{
        return;
    }
}

VixHandle hostHandle = VIX_INVALID_HANDLE; 
VixHandle jobHandle = VIX_INVALID_HANDLE;
VixHandle vmHandle = VIX_INVALID_HANDLE;
VixHandle snapshotHandle = VIX_INVALID_HANDLE;

int remote_fuzzer_fd = 0;

#define PORT 8000			//目标地址端口号
#define ADDR "192.168.51.128" //目标地址IP

int check_vm_server_status(){
    struct timeval timeout;
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;
    unsigned int iRemoteAddr = 0;
    struct sockaddr_in stRemoteAddr = {0};
    remote_fuzzer_fd = socket(AF_INET, SOCK_STREAM, 0);
    stRemoteAddr.sin_family = AF_INET;
	stRemoteAddr.sin_port = htons(PORT);
	inet_pton(AF_INET, ADDR, &iRemoteAddr);
	stRemoteAddr.sin_addr.s_addr=iRemoteAddr;

    int ret = setsockopt(remote_fuzzer_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));//avoid block cause fuzz freeze
	if (ret == -1) {
		puts("setsockopt err");
		return -1;
	}

    if(connect(remote_fuzzer_fd, (void *)&stRemoteAddr, sizeof(stRemoteAddr)) < 0){
        puts("cannot connect");
        return -1;
    }
    char buf[4] = {};
    if(read(remote_fuzzer_fd, buf, 4) != 4){
        puts("connect no hello");
        return -1;
    }
    if(strncmp(buf, "tsj", 4)!=0){
        puts("hello magic err");
        printf("%s\n",buf);
        return -1;
    }
}

void vix_init(){
    VixError err;
    char filepath[]="//home//kamille//vmware//Ubuntu 64-bit//Ubuntu 64-bit.vmx";
    puts("connct hosthandle");
    jobHandle = VixHost_Connect(VIX_API_VERSION,
        VIX_SERVICEPROVIDER_VMWARE_WORKSTATION,
        NULL, // hostName
        0, // hostPort
        NULL, // userName
        NULL, // password,
        0, // options
        VIX_INVALID_HANDLE, // propertyListHandle
        NULL, // callbackProc
        NULL); // clientData
    err = VixJob_Wait(jobHandle,
        VIX_PROPERTY_JOB_RESULT_HANDLE,
        &hostHandle,
        VIX_PROPERTY_NONE);
    if (VIX_OK != err) { 
        printf("connect error!\n");
        goto abort;
    }
    Vix_ReleaseHandle(jobHandle);

    puts("connct vmhandle");
    jobHandle = VIX_INVALID_HANDLE; 
    jobHandle = VixVM_Open(hostHandle,
        filepath,
        NULL, // callbackProc
        NULL); // clientData
    err = VixJob_Wait(jobHandle,
        VIX_PROPERTY_JOB_RESULT_HANDLE,
        &vmHandle,
        VIX_PROPERTY_NONE);
    if (VIX_OK != err) {
        printf("open host error!\n");
        goto abort;;
    }
    // Vix_ReleaseHandle(jobHandle);
    // jobHandle = VIX_INVALID_HANDLE;
    // // Power on the virtual machine before copying file.
    // jobHandle = VixVM_PowerOn(vmHandle,
    //                         0, // powerOnOptions
    //                         VIX_INVALID_HANDLE, // propertyListHandle
    //                         NULL, // callbackProc
    //                         NULL); // clientData

    // err = VixJob_Wait(jobHandle,VIX_PROPERTY_NONE);
    // if (VIX_OK != err) {
    //     puts("err power on");
    // // Handle the error...
    // goto abort;
    // }

    // Vix_ReleaseHandle(jobHandle); 
    // puts("vix tools wait");

    // jobHandle = VixVM_WaitForToolsInGuest(vmHandle,
    //                                         300, // timeoutInSeconds
    //                                         NULL, // callbackProc
    //                                         NULL); // clientData

    // err = VixJob_Wait(jobHandle, VIX_PROPERTY_NONE);
    // if (VIX_OK != err) {
    //     puts("wait for tool err");
    //     goto abort;
    // }

    // Vix_ReleaseHandle(jobHandle);

    // // Authenticate for guest operations.
    // jobHandle = VixVM_LoginInGuest(vmHandle,
    //                             "root", // userName
    //                             "123", // password
    //                             0, // options
    //                             NULL, // callbackProc
    //                             NULL); // clientData

    // err = VixJob_Wait(jobHandle, VIX_PROPERTY_NONE);
    // if (VIX_OK != err) {
    //     puts("auth guest err");
    //     goto abort;
    // }

    Vix_ReleaseHandle(jobHandle);
    puts("init vmware succ");
    return;
    abort:
    Vix_ReleaseHandle(jobHandle);
    Vix_ReleaseHandle(vmHandle);
    VixHost_Disconnect(hostHandle);
    exit(-1);
}

// int copy_file_to_vm(const char *host_path, const char *guest_path){
//     VixError err;
//     jobHandle = VixVM_CopyFileFromHostToGuest(vmHandle, host_path, guest_path, 0, VIX_INVALID_HANDLE, NULL, NULL);
//     err = VixJob_Wait(jobHandle, VIX_PROPERTY_NONE);
//     if(VIX_OK != err){
//         puts("cannot copy remote fuzzer to vm");
//         goto abort;
//     }
//     Vix_ReleaseHandle(jobHandle);
//     return 0;

//     abort:
//     Vix_ReleaseHandle(jobHandle);
//     Vix_ReleaseHandle(vmHandle);
//     VixHost_Disconnect(hostHandle);
// }


int connect_vm_and_resume(){
    
    VixError err;
    while(check_vm_server_status()<0){
        puts("vix init");
        vix_init();
        puts("vix inited");
        //remote_fuzzer is down,revert snapshot
        puts("get snapshot");
        err = VixVM_GetNamedSnapshot(vmHandle, SNAPSHOT_NAME ,&snapshotHandle);
        if(err != VIX_OK){
            puts("get fuzz_init snapshot err");
            goto abort;
        }
        jobHandle = jobHandle = VixVM_RevertToSnapshot(vmHandle,
                                   snapshotHandle,
                                   0, // options
                                   VIX_INVALID_HANDLE, // propertyListHandle
                                   NULL, // callbackProc
                                   NULL); // clientData
        err = VixJob_Wait(jobHandle, VIX_PROPERTY_NONE);
        if (VIX_OK != err) {
            puts("revert snapshot to fuzz_init err");
            goto abort;
        }
        Vix_ReleaseHandle(jobHandle);
        puts("get snapshot succ");

        // Wait until guest is completely booted.
        jobHandle = VixVM_WaitForToolsInGuest(vmHandle,
                                            300, // timeoutInSeconds
                                            NULL, // callbackProc
                                            NULL); // clientData

        err = VixJob_Wait(jobHandle, VIX_PROPERTY_NONE);
        if (VIX_OK != err) {
            puts("wait for tool err");
            goto abort;
        }

        Vix_ReleaseHandle(jobHandle);

        // Authenticate for guest operations.
        jobHandle = VixVM_LoginInGuest(vmHandle,
                                    "root", // userName
                                    "123", // password
                                    0, // options
                                    NULL, // callbackProc
                                    NULL); // clientData

        err = VixJob_Wait(jobHandle, VIX_PROPERTY_NONE);
        if (VIX_OK != err) {
            puts("auth guest err");
            goto abort;
        }

        Vix_ReleaseHandle(jobHandle);

        // jobHandle = VixVM_CopyFileFromHostToGuest(vmHandle, "/home/kamille/Documents/fuzz_eulerfs_workspace/image_fuzz/build/linux/x86_64/debug/remote_fuzzer", "/home/tsj/remote_fuzzer", 0, VIX_INVALID_HANDLE, NULL, NULL);
        // err = VixJob_Wait(jobHandle, VIX_PROPERTY_NONE);
        // if(VIX_OK != err){
        //     puts("cannot copy remote fuzzer to vm");
        //     goto abort;
        // }
        // Vix_ReleaseHandle(jobHandle);
        system("cp /home/kamille/Documents/fuzz_eulerfs_workspace/image_fuzz/build/linux/x86_64/debug/remote_fuzzer /home/kamille/Documents/fuzz_eulerfs_workspace/image_fuzz/fuzz_workspace");
        system("sync");
        //jobHandle = VixVM_RunProgramInGuest(vmHandle, "/home/tsj/remote_fuzzer", NULL, VIX_RUNPROGRAM_RETURN_IMMEDIATELY, VIX_INVALID_HANDLE, NULL, NULL);
        jobHandle = VixVM_RunScriptInGuest(vmHandle, "/usr/bin/bash", "echo \"tsj\" > /home/tsj/tsjjj\ndf >/home/tsj/ycmmm\ncp /mnt/hgfs/fuzz_workspace/remote_fuzzer /home/tsj/remote_fuzzer_ins\nnohup /home/tsj/remote_fuzzer_ins &",0,VIX_INVALID_HANDLE, NULL, NULL);
        err = VixJob_Wait(jobHandle, VIX_PROPERTY_NONE);
        if(VIX_OK != err){
            puts("cannot run remote fuzzer on vm");
            goto abort;
        }
        Vix_ReleaseHandle(jobHandle);
        puts("run remote fuzz succ");
        //while(1);
        // continue;
        
        abort:
        Vix_ReleaseHandle(jobHandle);
        Vix_ReleaseHandle(vmHandle);
        VixHost_Disconnect(hostHandle);

    }

    return 0;
}



int execute_img_process(const char *img_path){

    // stage one
    if( access(img_path, F_OK) != 0){
        printf("file not exist");
        return -1;
    }

    //stage two
    if(connect_vm_and_resume()<0){
        puts("err fuzz init");
        return -1;
    }

    //stage three
    //scp too slow, switch to vmware api
    char cmd[255] = {0};
    // snprintf(cmd ,254, "scp %s %s", img_path, DEST_SCP);
    // puts(cmd);
    // int cmd_ret = system(cmd);
    // if(cmd_ret < 0){
    //     puts("cannot send input data via scp");
    //     return -1;
    // }
    memset(cmd, 0, 255);
    snprintf(cmd, 254, "cp %s %s",img_path, "/home/kamille/Documents/fuzz_eulerfs_workspace/image_fuzz/fuzz_workspace/");
    system(cmd);
    int len = snprintf(cmd, 254, "/mnt/hgfs/fuzz_workspace/%s", __xpg_basename(img_path));
    //copy_file_to_vm(img_path, cmd);
    
    puts(cmd);
    write(remote_fuzzer_fd, cmd, strlen(cmd)+1);//tell remote fuzzer path of input

    //stage four,five
    //we right path on stage three, cmd will run by remote_fuzzer

    //stage six
    //recv cov data, and dmesg magic msg hahaha
    char buf[32] = {0};
    unsigned long long *ptr = buf;
    uint16_t prev_loc = 0;
    while(1){
        int len = read(remote_fuzzer_fd, buf, 8);
        if(strstr(buf, "fuck")==0 && strstr(buf, "sad")==0){
            unsigned long long addr = *ptr;
            if(addr>0xffffffffc0000000){
                //printf("0x%llx\n", addr);
                uint16_t cur_loc = hsiphash_static(&addr, sizeof(unsigned long))&0xffff; //(addr&0x2ffff)/8;
                __afl_area_ptr[cur_loc ^ prev_loc]++;
                prev_loc = cur_loc >> 1;
            }
            //0xffffffffc12d0000  0x2eba4
        }else{
            break;
        }
    }
    if(strstr(buf, "fuck")){
        // get panic on vm, kill myself for afl
        return -2;
    }else{
        return 0;
    }

}


int main(int argc, char** argv)
{
    freopen("out.txt","w",stdout);
    init_shm();
    afl_forkserver(argv[1]);
    // here to execute
    /*
     1. read input data path from arg
     2. revert vm to snapshot  //check fuzzed_vm running status.if remote_fuzzer not running revert to snapshot fuzz_init and copy remote_fuzzer to vm,run
     3. send input data to vm 
     4. run command on vm :(1) dd if=input.img of=/dev/pmem0 (2)mount -t eulerfs /dev/pmem0 mnt_test
     5. do some file operation on mnt_test like open read write readdir then umount
     6. check status: (1) dmesg output (2) vm is running
     7. raise sigsev and shutdown vm if kernel panic or vm shutdown
    */
    int ret = execute_img_process(argv[1]);
    //ret = execute_img_process(argv[2]);
    if(ret == -1){
        printf("error via process\n");
    }else if(ret == -2){
        printf("detect panic on vm, raise\n");
        abort();
    }
    return 0;
}
