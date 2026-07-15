/*  
 * Process reaper - 'pr' for short.
 *
 * Scans /proc for Zombie, orphans and dangling orphans.
 *
 * Build with gcc -O2 -Wall process_reaper.c -o pr
 */

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
  NULL
};

/* Functions */
void volatile sig_handler(int signum){
  fprintf(stderr, "[I] Received signal %d, exiting.\n", signum);
  early_exit = true;
  loop = false;
}

static void usage(const char *progname){
  fprintf(stdout, "Usage: %s [options]\n", progname);
  fprintf(stdout, "Options:\n");
  fprintf(stdout, "  -l, --loop           Loop and report every interval seconds.\n");
  fprintf(stdout, "  -i, --interval N     Set the interval in seconds (default: %d).\n", DEFAULT_INTERVAL);
  fprintf(stdout, "  -h, --help           Show this help message.\n");
  fprintf(stdout, "  -k, --kill           Kill zombies and orphans. Be real careful when running with this option.\n");
}

static void clear_screen() {
  fflush(stdout);
  const char *CLEAR_SCREEN_ANSI = "\e[1;1H\e[2J";
  write(STDOUT_FILENO, CLEAR_SCREEN_ANSI, strlen(CLEAR_SCREEN_ANSI));
  fflush(stdout);
}

static void kill_process(int pid){
  if (kill(pid, SIGKILL) == 0){
    fprintf(stdout, "[I] Killed process %d.\n", pid);
  } else {
    fprintf(stderr, "[E] Failed to kill process %d.\n", pid);
  }
}

static bool is_pid(const char *path){
  if (*path == '\0')
    return false;
  for (const char *p = path; *p != '\0'; p++){
    if(!isdigit((unsigned char)*p))
      return false;
  }
  return true;
}

static proc_info_t *find_by_pid(int pid){
  for (int i = 0; i < proc_count ; ++i)
    if (procs[i].pid == pid) return &procs[i];
  return NULL; 
} 

static double get_uptime_seconds(void){
  FILE *f = fopen("/proc/uptime", "r");
  if (!f) return -1.0;
  double uptime = -1.0;
  if (fscanf(f, "%lf", &uptime) != 1) uptime = -1.0;
  fclose(f);
  return uptime;
}

static double get_proc_age(int pid, int uptime){
  double proc_start_sec = 
    (double)procs[pid].starttime_ticks / sysconf(_SC_CLK_TCK);
  return uptime - proc_start_sec;
}

static int get_screen_process(int pid){
  while (pid > 1){
    proc_info_t *proc = find_by_pid(pid);
    if (!proc) return -1;
    if (strcmp(proc->name, "screen") == 0) return proc->pid;
    pid = proc->ppid;
  }
  return -1;
}

/* Reads the raw NUL-separated cmdline into out, and reports how many
 * bytes were actually read via *len_out (trailing NULs trimmed). 
 * Returns 0 on success, -1 on failure. */
static int read_proc_cmdline(int pid, char *out, size_t out_size, size_t *len_out){
  char path[PATH_LEN];
  snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

  FILE *f = fopen(path, "r");
  if (!f) return -1;

  size_t n = fread(out, 1, out_size, f);
  fclose(f);

  if (n == 0) return -1;

  /* cmdline often has a trailing NUL */
  while (n > 0 && out[n - 1] == '\0') n--;
  if (n == 0) return -1;

  *len_out = n;
  return 0;
}

/* Given a raw cmdline buffer (as filled by read_proc_cmdline) and its
 * length, extracts the last NUL-separated token into out. */
static int get_last_cmdline_arg(const char *cmdline, size_t cmdline_len, char *out, size_t out_size){
  if (cmdline_len == 0) return -1;

  size_t end = cmdline_len;
  size_t start = end;
  while (start > 0 && cmdline[start - 1] != '\0') start--;

  size_t len = end - start;
  if (len >= out_size) len = out_size - 1;

  memcpy(out, cmdline + start, len);
  out[len] = '\0';

  return 0;
}

static int read_proc_stat(int pid, char *name_out, char *state_out, int *ppid_out, long long *starttime_out){
  char path[PATH_LEN];
  snprintf(path, sizeof(path), "/proc/%d/stat", pid);

  FILE *f = fopen(path, "r");
  if (!f) return -1;

  char buf[BUFF_LEN];
  if(!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
  fclose(f);

  /* get name */
  char *open_paren  = strchr(buf, '(');
  char *close_paren = strrchr(buf, ')');
  if (!open_paren || !close_paren || close_paren < open_paren) return -1;
 
  size_t len = close_paren - open_paren - 1;
  if (len >= NAME_LEN) len = NAME_LEN - 1;
  strncpy(name_out, open_paren + 1, len);
  name_out[len] = '\0';
 
  /* get rest of parameters */
  char *rest = close_paren + 2;
  /* Start at field 3 */
  if (sscanf(rest,
    "%c %d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %lld",
    state_out, ppid_out, starttime_out) != 3) return -1;

  return 0;
}

static void clear_proc_list(void){
  proc_count = 0;
  memset(procs, 0, sizeof(procs));
}

static void scan_proc(void){
  DIR *dir;
  struct dirent *entry;

  if ((dir = opendir("/proc/"))!=NULL){
    /* While reading /proc/ directory */
    while ((entry=readdir(dir))!=NULL){
      /* If is a pid folder */
      if(is_pid(entry->d_name)){
        /* Fill procs for this pid */
        procs[proc_count].pid = atoi(entry->d_name);
        if (read_proc_stat(procs[proc_count].pid, procs[proc_count].name,
            &procs[proc_count].state, &procs[proc_count].ppid,
            &procs[proc_count].starttime_ticks) != 0){
          fprintf(stderr, "[E] Could not read /proc/%d/stat file.\n", 
            procs[proc_count].pid);
        }

        if(++proc_count >= MAX_PROC){
          fprintf(stderr, "[W] Reached max number of processes (%d).\n",
            proc_count);
          closedir(dir);
          return;
        }
      }
    }
    closedir(dir);
  }
}

static bool is_systemd_managed(int pid){
  char path[PATH_LEN];
  snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);

  FILE *f = fopen(path, "r");
  if (!f) return false;

  char buf[BUFF_LEN];
  bool managed = false;

  while (fgets(buf, sizeof(buf), f)){
    if (strstr(buf, "/system.slice/") != NULL ||
        strstr(buf, "/init.scope") != NULL ||
        strstr(buf, ".service") != NULL) {
      managed = true;
      break;
    }
  }

  fclose(f);
  return managed;
}

static bool is_known_daemon(const char *name){
  for (int i = 0; KNOWN_DAEMON_PREFIXES[i] != NULL; ++i){
    size_t plen = strlen(KNOWN_DAEMON_PREFIXES[i]);
    if (strncmp(name, KNOWN_DAEMON_PREFIXES[i], plen) == 0) {
      return true;
    }
  }
  return false;
}

static int kill_process_list(void){
  fprintf(stdout, "[I] Killing %d processes...\n", kill_count);
  for (int i = 0; i < kill_count; ++i) {
    kill_process(kill_pids[i]);
  }
  kill_count = 0; // Reset kill count after processing
  return 0;
}

static void report_zombies(void){
  fprintf(stdout, "=== Zombies ===\n");
  fprintf(stdout, "stat PID comm PPID pcom age screen\n");

  double uptime = get_uptime_seconds();

  for (int i = 0; i < proc_count; ++i){
    if (read_proc_stat(procs[i].pid, procs[i].name, 
        &procs[i].state, &procs[i].ppid, &procs[i].starttime_ticks) == 0){

      if (procs[i].state != 'Z') continue;

      /* Get parent name */
      proc_info_t *parent = find_by_pid(procs[i].ppid);
      const char *parent_name = parent ? parent->name : "?";

      /* Get session name */
      char session[NAME_LEN] = "?";
      int screen_pid = get_screen_process(procs[i].pid);
      if (screen_pid != -1) {
        char cmdline[BUFF_LEN];
        size_t cmdline_len = 0;
        if (read_proc_cmdline(screen_pid, cmdline, sizeof(cmdline), &cmdline_len) == 0) {
          get_last_cmdline_arg(cmdline, cmdline_len, session, sizeof(session));
        }
      }

      /* Add process to kill list */
      if (kill_targets)
        kill_pids[kill_count++] = procs[i].pid;

      /* Print everything */
      fprintf(stdout, "%c %d %s %d %s %.0f %s\n",
        procs[i].state, procs[i].pid, procs[i].name, procs[i].ppid, 
        parent_name, get_proc_age(i, uptime), session);

    } else {
      fprintf(stderr, "[E] Could not read /proc/%d/stat file.\n", procs[i].pid);
    }
  }
}

static void report_orphans(void){
  fprintf(stdout, "=== Orphans ===\n");
  fprintf(stdout, "stat PID comm age\n");

  double uptime = get_uptime_seconds();

  for (int i = 0; i < proc_count; ++i){
    if (read_proc_stat(procs[i].pid, procs[i].name, 
        &procs[i].state, &procs[i].ppid, &procs[i].starttime_ticks) == 0){

      if ((procs[i].ppid == 1) && (!is_systemd_managed(procs[i].pid)) &&
          (!is_known_daemon(procs[i].name))) {

        /* Add process to kill list */
        if (kill_targets)
          kill_pids[kill_count++] = procs[i].pid;

        /* Print everything */
        fprintf(stdout, "%c %d %s %.0f\n",
          procs[i].state, procs[i].pid, procs[i].name, get_proc_age(i, uptime));
      }

    } else {
      fprintf(stderr, "[E] Could not read /proc/%d/stat file.\n", procs[i].pid);
    }
  }
}

/* Entry point */
int main(int argc, char *argv[]){
  int interval = DEFAULT_INTERVAL;

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  for (int i = 1; i < argc; ++i){
    if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--loop") == 0){
      loop = true;
    } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interval") == 0){
      if (i + 1 < argc){
        interval = atoi(argv[++i]);
        if (interval <= 0) interval = DEFAULT_INTERVAL;
        loop = true;
      }
    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0){
      usage(argv[0]);
      return 0;
    } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--kill") == 0){
      kill_targets = true;
    }
  }

  if (kill_targets){
    fprintf(stdout, "[I]: You have enabled the kill option. This will terminate zombies and orphans.\n");
    for (int i = 10; i > 0; --i) {
      fprintf(stdout, "[I] Waiting, %d seconds to continue...\r", i);
      fflush(stdout);
      sleep(1);
      if (early_exit) {
        fprintf(stdout, "\n[I] Early exit requested. Aborting kill operation.\n");
        return 0;
      }
    }
    fprintf(stdout, "\n");
    if(loop) loop=false; // Disable loop if kill is enabled to avoid repeated killing
  }
 
  do{
    if(loop) clear_screen();
    clear_proc_list();
    scan_proc();
    report_zombies();
    report_orphans();
    if (kill_targets && kill_count > 0) kill_process_list();
  } while (loop && sleep(interval) == 0);

  return 0;
}
