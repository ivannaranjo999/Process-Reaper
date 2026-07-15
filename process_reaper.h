#ifndef PROCESS_REAPER_H
#define PROCESS_REAPER_H

/* Includes */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>

/* Constants */
#define MAX_PROC 4096
#define NAME_LEN 256
#define PATH_LEN 128
#define BUFF_LEN 1024
#define DEFAULT_INTERVAL 5

/* Type definitions */
typedef struct {
  int pid;
  int ppid;
  char name[NAME_LEN];
  char state;
  long long starttime_ticks;
} proc_info_t;

/* Global variables */
static proc_info_t procs[MAX_PROC];
static int proc_count = 0;
static int kill_pids[MAX_PROC];
static int kill_count = 0;
static bool loop = false;
static bool early_exit = false;
static bool kill_targets = false;

/* Names of processes that legitimately self-daemonize (double-fork +
 * detach) and are therefore expected orphans.
 *
 * This list is not complete, if some process is a daemon
 * or self-daemonizes and it is not listed here, please create a PR
 * in github.
 *
 * This list contains truncated prefixes of process names */
static const char *KNOWN_DAEMON_PREFIXES[] = {
  "screen",
  "gpg-agent",
  "dbus-daemon",
  "dbus-kill-proce",
  "gvfsd",
  "at-spi",
  "ibus-",
  "xdg-permission-",
  "xdg-desktop-",
  "pk-command-not-",
  "login",
  NULL
};

#endif
