#include "wait.h"


// 网上抄的

int waitpid_timeout(pid_t pid, int mseconds)
{
 int status = 0;
  sigset_t mask, orig_mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &mask, &orig_mask) < 0) {
   perror("sigprocmask");
   return 1;
 }
 else {
   struct timespec timeout;
   timeout.tv_sec = mseconds / 1000;
   timeout.tv_nsec = ( mseconds % 1000 ) * 1000000;
   do {
      if (sigtimedwait(&mask, NULL, &timeout) < 0) {
          if (errno == EINTR) {
             /* Interrupted by a signal other than SIGCHLD. */
            continue;
          }
          else if (errno == EAGAIN) {
             printf("Timeout, killing child\n");
             kill(pid, SIGKILL);
          }
         else {
            perror("sigtimedwait");
            return 1;
         }
     }
     else puts("got child quit signal");
     break;
   } while (1);
  if (waitpid(pid, &status, 0) < 0) {
     perror("waitpid");
     return status;
   }
   return 0;
  }
}