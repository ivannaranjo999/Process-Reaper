// make_zombie.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
  pid_t pid = fork();

  if (pid == 0) {
    printf("Child (PID %d) exiting now.\n", getpid());
    exit(0);
  } else if (pid > 0) {
    printf("Parent (PID %d), child PID %d will become a zombie.\n", getpid(), pid);
    printf("Parent sleeping for 5 minutes...\n");
    sleep(300);
  } else {
    perror("fork failed");
    return 1;
  }

  return 0;
}