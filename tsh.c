/* 
 * tsh - A tiny shell program with job control
 * 
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

/* Misc manifest constants */
#define MAXLINE    1024   /* max line size */
#define MAXARGS     128   /* max args on a command line */
#define MAXJOBS      16   /* max jobs at any point in time */
#define MAXJID    1<<16   /* max job ID */

/* Job states */
#define UNDEF 0 /* undefined */
#define FG 1    /* running in foreground */
#define BG 2    /* running in background */
#define ST 3    /* stopped */

/* 
 * Jobs states: FG (foreground), BG (background), ST (stopped)
 * Job state transitions and enabling actions:
 *     FG -> ST  : ctrl-z
 *     ST -> FG  : fg command
 *     ST -> BG  : bg command
 *     BG -> FG  : fg command
 * At most 1 job can be in the FG state.
 */

/* Global variables */
extern char **environ;      /* defined in libc */
char prompt[] = "tsh> ";    /* command line prompt (DO NOT CHANGE) */
int verbose = 0;            /* if true, print additional output */
int nextjid = 1;            /* next job ID to allocate */
char sbuf[MAXLINE];         /* for composing sprintf messages */

struct job_t {              /* The job struct */
    pid_t pid;              /* job PID */
    int jid;                /* job ID [1, 2, ...] */
    int state;              /* UNDEF, BG, FG, or ST */
    char cmdline[MAXLINE];  /* command line */
};
struct job_t jobs[MAXJOBS]; /* The job list */
/* End global variables */


/* Function prototypes */

/* Here are the functions that you will implement */
void eval(char *cmdline);
int builtin_cmd(char **argv);
void do_bgfg(char **argv);
void waitfg(pid_t pid);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);

/* Here are helper routines that we've provided for you */
int parseline(const char *cmdline, char **argv); 
void sigquit_handler(int sig);

void clearjob(struct job_t *job);
void initjobs(struct job_t *jobs);
int maxjid(struct job_t *jobs); 
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline);
int deletejob(struct job_t *jobs, pid_t pid); 
pid_t fgpid(struct job_t *jobs);
struct job_t *getjobpid(struct job_t *jobs, pid_t pid);
struct job_t *getjobjid(struct job_t *jobs, int jid); 
int pid2jid(pid_t pid); 
void listjobs(struct job_t *jobs);

void usage(void);
void unix_error(char *msg);
void app_error(char *msg);
typedef void handler_t(int);
handler_t *Signal(int signum, handler_t *handler);

/* wrapper functions to handle system call error */
pid_t Fork(void);
int Execve(const char *path, char *const argv[], char *const envp[]);
int Setpgid(pid_t pid, pid_t pgid);
int Kill(pid_t pid, int sig);
pid_t Waitpid(pid_t pid, int *status, int options);
int Sigemptyset(sigset_t *set);
int Sigfillset(sigset_t *set);
int Sigaddset(sigset_t *set, int signum);
int Sigdelset(sigset_t *set, int signum);
int Sigprocmask(int how, const sigset_t *set, sigset_t *oset);
int Sigsuspend(const sigset_t *sigmask);

/*
 * main - The shell's main routine 
 */
int main(int argc, char **argv) 
{
    char c;
    char cmdline[MAXLINE];
    int emit_prompt = 1; /* emit prompt (default) */

    /* Redirect stderr to stdout (so that driver will get all output
     * on the pipe connected to stdout) */
    dup2(1, 2);

    /* Parse the command line */
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h':             /* print help message */
            usage();
        break;
        case 'v':             /* emit additional diagnostic info */
            verbose = 1;
        break;
        case 'p':             /* don't print a prompt */
            emit_prompt = 0;  /* handy for automatic testing */
        break;
    default:
            usage();
    }
    }

    /* Install the signal handlers */

    /* These are the ones you will need to implement */
    Signal(SIGINT,  sigint_handler);   /* ctrl-c */
    Signal(SIGTSTP, sigtstp_handler);  /* ctrl-z */
    Signal(SIGCHLD, sigchld_handler);  /* Terminated or stopped child */

    /* This one provides a clean way to kill the shell */
    Signal(SIGQUIT, sigquit_handler); 

    /* Initialize the job list */
    initjobs(jobs);

    /* Execute the shell's read/eval loop */
    while (1) {

    /* Read command line */
    if (emit_prompt) {
        printf("%s", prompt);
        fflush(stdout);
    }
    if ((fgets(cmdline, MAXLINE, stdin) == NULL) && ferror(stdin))
        app_error("fgets error");
    if (feof(stdin)) { /* End of file (ctrl-d) */
        fflush(stdout);
        exit(0);
    }

    /* Evaluate the command line */
    eval(cmdline);
    fflush(stdout);
    fflush(stdout);
    } 

    exit(0); /* control never reaches here */
}
  
/* 
 * eval - Evaluate the command line that the user has just typed in
 * 
 * If the user has requested a built-in command (quit, jobs, bg or fg)
 * then execute it immediately. Otherwise, fork a child process and
 * run the job in the context of the child. If the job is running in
 * the foreground, wait for it to terminate and then return.  Note:
 * each child process must have a unique process group ID so that our
 * background children don't receive SIGINT (SIGTSTP) from the kernel
 * when we type ctrl-c (ctrl-z) at the keyboard.  
*/
void eval(char *cmdline) 
{

  int bg; /* background job? */
  char *argv[MAXLINE]; /* holds parsed command line */
  sigset_t mask; /* blocked bit vector */
  pid_t pid;
  struct job_t *job_ptr; /* points to a job */

  /* parse the command line */
  bg = parseline(cmdline, argv);

  /* ignore empty lines */
  if(argv[0] == NULL)
    return;

  /* built-in command? */
  if(builtin_cmd(argv)) /* if so execute it immediately and return to the main loop */
    return;

  /* execute the command as an executable file */
  /* block SIGCHLD to avoid race conditions */
  Sigemptyset(&mask);
  Sigaddset(&mask, SIGCHLD);
  Sigprocmask(SIG_BLOCK, &mask, NULL);

  /* child process */
  if((pid = Fork()) == 0){
    Setpgid(0, 0); /* gpid <- pid */
    Sigprocmask(SIG_UNBLOCK, &mask, NULL); /* unlock SIGCHLD */

    /* load program */
    if(Execve(argv[0], argv, environ) < 0){ /* detect error */
      printf("%s: Command not found\n", argv[0]);
      fflush(stdout);
      exit(0);
    }
  }

  /* parent process */
  if(!bg){
    addjob(jobs, pid, FG, cmdline); /* add the job to the job list as a FG job */
  }
  else{
    addjob(jobs, pid, BG, cmdline); /* add the job to the job list as a BG job */

    /* show information about the job */
    job_ptr = getjobpid(jobs, pid);
    printf("[%d] (%d) %s", job_ptr->jid, job_ptr->pid, job_ptr->cmdline);
  }
  Sigprocmask(SIG_UNBLOCK, &mask, NULL); /* unlock SIGCHLD */

  /* wait for a FG job to terminate */
  if(!bg) /* if FG */
    waitfg(pid);
    
  return;
}

/* 
 * parseline - Parse the command line and build the argv array.
 * 
 * Characters enclosed in single quotes are treated as a single
 * argument.  Return true if the user has requested a BG job, false if
 * the user has requested a FG job.  
 */
int parseline(const char *cmdline, char **argv) 
{

    static char array[MAXLINE]; /* holds local copy of command line */
    char *buf = array;          /* ptr that traverses command line */
    char *delim;                /* points to first space delimiter */
    int argc;                   /* number of args */
    int bg;                     /* background job? */

    strcpy(buf, cmdline);
    buf[strlen(buf)-1] = ' ';  /* replace trailing '\n' with space */
    while (*buf && (*buf == ' ')) /* ignore leading spaces */
    buf++;

    /* Build the argv list */
    argc = 0;
    if (*buf == '\'') {
    buf++;
    delim = strchr(buf, '\'');
    }
    else {
    delim = strchr(buf, ' ');
    }

    while (delim) {
    argv[argc++] = buf;
    *delim = '\0';
    buf = delim + 1;
    while (*buf && (*buf == ' ')) /* ignore spaces */
           buf++;

    if (*buf == '\'') {
        buf++;
        delim = strchr(buf, '\'');
    }
    else {
        delim = strchr(buf, ' ');
    }
    }
    argv[argc] = NULL;
    
    if (argc == 0)  /* ignore blank line */
    return 1;

    /* should the job run in the background? */
    if ((bg = (*argv[argc-1] == '&')) != 0) {
    argv[--argc] = NULL;
    }
    return bg;
}

/* 
 * builtin_cmd - If the user has typed a built-in command then execute
 *    it immediately.  
 *    If the command is a built-in command then return true otherwise return false.
 */
int builtin_cmd(char **argv) 
{
  if(!strcmp(*argv, "quit"))
    exit(0); /* terminate the program */
  else if(!strcmp(*argv, "jobs")){
    listjobs(jobs);
    return 1;
  }
  else if(!strcmp(*argv, "bg") || !strcmp(*argv, "fg")){
    do_bgfg(argv);
    return 1;
  }

  return 0;     /* not a builtin command */
}

/* 
 * do_bgfg - Execute the builtin bg and fg commands
 */
void do_bgfg(char **argv) 
{
  int id; /* holds PID or jobid */
  int i;
  int is_job = 0; /* holds 1 if the argument is a jobid 0 if it is a PID */
  struct job_t *job_ptr;

  /* check if there is an argument */
  if(argv[1] == NULL) {
    printf("%s command requires PID or %%jobid argument\n", *argv);
    return;
  }

  /* PID or jobid? */
  if(argv[1][0] == '%')
    is_job = 1;

  /* return if there is an illegal character */
  for(i = is_job; argv[1][i] != '\0'; i++){
    if(isalpha(argv[1][i])){
      printf("%s: argument must be a PID or %%jobid\n", *argv);
      return;
    }
  }
  id = atoi(argv[1]+is_job); /* extract PID/jobid */

  /* get a pointer to the target job by PID/jobid */
  if(!is_job) /* if PID */
    job_ptr = getjobpid(jobs, id); /* by PID */
  else
    job_ptr = getjobjid(jobs, id); /* by jobid */

  /* return if the the argument is an illegal PID/jobid */
  if(job_ptr == NULL){
    if(!is_job) /* if PID */
      printf("(%d): No such process\n", id);
    else
      printf("%%%d: No such job\n", id);
    return;
  }

  /* do bg/fg command */
  if(!strcmp(*argv, "bg")){
    Kill(-(job_ptr->pid), SIGCONT); /* send a SIGCONT signal */
    job_ptr->state = BG; /* change state to BG */
    printf("[%d] (%d) %s", job_ptr->jid, job_ptr->pid, job_ptr->cmdline); /* show information about the job */
  }
  else if(!strcmp(*argv, "fg")){
    Kill(-(job_ptr->pid), SIGCONT); /* send a SIGCONT signal */
    job_ptr->state = FG; /* change state to FG */
    waitfg(job_ptr->pid); /* block until the process terminates */
  }

    return;
}

/* 
 * waitfg - Block until process pid is no longer the foreground process
 */
void waitfg(pid_t pid)
{
  sigset_t mask; /* blocked bit vector */

  /* wait for a SIGCHLD, SIGINT or SIGTSTP signal */
  Sigfillset(&mask);
  Sigdelset(&mask,SIGCHLD);
  Sigdelset(&mask,SIGINT);
  Sigdelset(&mask,SIGTSTP);
  Sigsuspend(&mask);

  /* if there is still a FG job then wait */
  if(fgpid(jobs))
    Sigsuspend(&mask);

  return;
}

/*****************
 * Signal handlers
 *****************/

/* 
 * sigchld_handler - The kernel sends a SIGCHLD to the shell whenever
 *     a child job terminates (becomes a zombie), or stops because it
 *     received a SIGSTOP or SIGTSTP signal. The handler reaps all
 *     available zombie children, but doesn't wait for any other
 *     currently running children to terminate.  
 */
void sigchld_handler(int sig)
{
  pid_t pid;
  int status;
  struct job_t *job_ptr;

  /* reap zombie children in no particular order */
  while((pid = Waitpid(-1, &status, WNOHANG|WUNTRACED)) > 0){

    /* remove the job from the job list */
    if(!WIFSTOPPED(status)){ /* if got a SIGTSTP */
      if(WIFSIGNALED(status)){ /* if terminated by a signal */
        job_ptr = getjobpid(jobs, pid);
        printf("Job [%d] (%d) terminated by signal %d\n", job_ptr->jid, job_ptr->pid, WTERMSIG(status)); /* print the signal number */
      }
      if(!deletejob(jobs, pid)) /* remove the job from the job list */
        printf("Error: couldn't delete a job\n");
    }
    else{
      job_ptr = getjobpid(jobs, pid);
      if(job_ptr->state != ST){
        sigtstp_handler(sig); /* call sigtstp_handler to change the state and show info */
      }
    }
  }
    return;
}

/* 
 * sigint_handler - The kernel sends a SIGINT to the shell whenver the
 *    user types ctrl-c at the keyboard.  Catch it and send it along
 *    to the foreground job.  
 */
void sigint_handler(int sig) 
{
  pid_t pid = fgpid(jobs); /* get PID of the current FG job */

  /* if there is no FG job then return */
  if(!pid)
    return;
  Kill(-pid, SIGINT); /* send SIGINT to the current FG job */

  return;
}

/*
 * sigtstp_handler - The kernel sends a SIGTSTP to the shell whenever
 *     the user types ctrl-z at the keyboard. Catch it and suspend the
 *     foreground job by sending it a SIGTSTP.  
 */
void sigtstp_handler(int sig) 
{
  struct job_t *job_ptr;
  pid_t pid = fgpid(jobs); /* get PID of the current FG job */

  /* if there is no FG job then return */
  if(!pid)
    return;
  Kill(-pid, SIGTSTP); /* send SIGTSTP to the current FG job */  
  job_ptr = getjobpid(jobs, pid);
  job_ptr->state = ST; /* FG -> ST */
  printf("Job [%d] (%d) stopped by signal %d\n", job_ptr->jid, job_ptr->pid, SIGTSTP); /* show the status of the job */

  return;
}

/*********************
 * End signal handlers
 *********************/

/***********************************************
 * Helper routines that manipulate the job list
 **********************************************/

/* clearjob - Clear the entries in a job struct */
void clearjob(struct job_t *job) {
    job->pid = 0;
    job->jid = 0;
    job->state = UNDEF;
    job->cmdline[0] = '\0';
}

/* initjobs - Initialize the job list */
void initjobs(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++)
    clearjob(&jobs[i]);
}

/* maxjid - Returns largest allocated job ID */
int maxjid(struct job_t *jobs) 
{
    int i, max=0;

    for (i = 0; i < MAXJOBS; i++)
    if (jobs[i].jid > max)
        max = jobs[i].jid;
    return max;
}

/* addjob - Add a job to the job list */
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline) 
{
    int i;
    
    if (pid < 1)
    return 0;

    for (i = 0; i < MAXJOBS; i++) {
    if (jobs[i].pid == 0) {
        jobs[i].pid = pid;
        jobs[i].state = state;
        jobs[i].jid = nextjid++;
        if (nextjid > MAXJOBS)
        nextjid = 1;
        strcpy(jobs[i].cmdline, cmdline);
        if(verbose){
            printf("Added job [%d] %d %s\n", jobs[i].jid, jobs[i].pid, jobs[i].cmdline);
            }
            return 1;
    }
    }
    printf("Tried to create too many jobs\n");
    return 0;
}

/* deletejob - Delete a job whose PID=pid from the job list */
int deletejob(struct job_t *jobs, pid_t pid) 
{
    int i;

    if (pid < 1)
    return 0;

    for (i = 0; i < MAXJOBS; i++) {
    if (jobs[i].pid == pid) {
        clearjob(&jobs[i]);
        nextjid = maxjid(jobs)+1;
        return 1;
    }
    }
    return 0;
}

/* fgpid - Return PID of current foreground job, 0 if no such job */
pid_t fgpid(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++)
    if (jobs[i].state == FG)
        return jobs[i].pid;
    return 0;
}

/* getjobpid  - Find a job (by PID) on the job list */
struct job_t *getjobpid(struct job_t *jobs, pid_t pid) {
    int i;

    if (pid < 1)
    return NULL;
    for (i = 0; i < MAXJOBS; i++)
    if (jobs[i].pid == pid)
        return &jobs[i];
    return NULL;
}

/* getjobjid  - Find a job (by JID) on the job list */
struct job_t *getjobjid(struct job_t *jobs, int jid) 
{
    int i;

    if (jid < 1)
    return NULL;
    for (i = 0; i < MAXJOBS; i++)
    if (jobs[i].jid == jid)
        return &jobs[i];
    return NULL;
}

/* pid2jid - Map process ID to job ID */
int pid2jid(pid_t pid) 
{
    int i;

    if (pid < 1)
    return 0;
    for (i = 0; i < MAXJOBS; i++)
    if (jobs[i].pid == pid) {
            return jobs[i].jid;
        }
    return 0;
}

/* listjobs - Print the job list */
void listjobs(struct job_t *jobs) 
{
    int i;
    
    for (i = 0; i < MAXJOBS; i++) {
    if (jobs[i].pid != 0) {
        printf("[%d] (%d) ", jobs[i].jid, jobs[i].pid);
        switch (jobs[i].state) {
        case BG: 
            printf("Running ");
            break;
        case FG: 
            printf("Foreground ");
            break;
        case ST: 
            printf("Stopped ");
            break;
        default:
            printf("listjobs: Internal error: job[%d].state=%d ", 
               i, jobs[i].state);
        }
        printf("%s", jobs[i].cmdline);
    }
    }
}
/******************************
 * end job list helper routines
 ******************************/


/***********************
 * Other helper routines
 ***********************/

/*
 * usage - print a help message
 */
void usage(void) 
{
    printf("Usage: shell [-hvp]\n");
    printf("   -h   print this message\n");
    printf("   -v   print additional diagnostic information\n");
    printf("   -p   do not emit a command prompt\n");
    exit(1);
}

/*
 * unix_error - unix-style error routine
 */
void unix_error(char *msg)
{
    fprintf(stdout, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

/*
 * app_error - application-style error routine
 */
void app_error(char *msg)
{
    fprintf(stdout, "%s\n", msg);
    exit(1);
}

/*
 * Signal - wrapper for the sigaction function
 */
handler_t *Signal(int signum, handler_t *handler) 
{
    struct sigaction action, old_action;

    action.sa_handler = handler;  
    sigemptyset(&action.sa_mask); /* block sigs of type being handled */
    action.sa_flags = SA_RESTART; /* restart syscalls if possible */

    if (sigaction(signum, &action, &old_action) < 0)
    unix_error("Signal error");
    return (old_action.sa_handler);
}

/*
 * sigquit_handler - The driver program can gracefully terminate the
 *    child shell by sending it a SIGQUIT signal.
 */
void sigquit_handler(int sig) 
{
    printf("Terminating after receipt of SIGQUIT signal\n");
    exit(1);
}

/*
 * Fork - wrapper for the fork function
 */
pid_t Fork(void){
  pid_t pid;

  if((pid = fork()) < 0)
    unix_error("Fork error");
  return pid;
}

/*
 * Execve - wrapper for the execve function
 */
int Execve(const char *path, char *const argv[], char *const envp[]){
  int status;

  if(((status = execve(path, argv, envp)) < 0) && (errno != ENOENT)) /* ignore ENOENT error */
    unix_error("Execve error");
  return status;
}

/*
 * Setpgid - wrapper for the setpgid function
 */
int Setpgid(pid_t pid, pid_t pgid){
  int status;

  if((status = setpgid(pid, pid)) < 0)
    unix_error("Setpgid error");
  return status;
}

/*
 * Kill - wrapper for the kill function
 */
int Kill(pid_t pid, int sig){
  int status;

  if((status = kill(pid, sig)) < 0)
    unix_error("Kill error");
  return status;
}

/*
 * Waitpid - wrapper for the waitpid function
 */
pid_t Waitpid(pid_t pid, int *status, int options){

  if(((pid = waitpid(pid, status, options)) < 0) && (errno != ECHILD)) /* ignore unwaited-for child process error to keep the program running */
    unix_error("Waitpid error");
  return pid;
}

/*
 * Sigemptyset - wrapper for the sigemptyset function
 */
int Sigemptyset(sigset_t *set){
  int status;

  if((status = sigemptyset(set)) < 0)
    unix_error("Sigemptyset error");
  return status;
}

/*
 * Sigfillset - wrapper for the sigfillset function
 */
int Sigfillset(sigset_t *set){
  int status;

  if((status = sigfillset(set)) < 0)
    unix_error("Sigfillset error");
  return status;
}

/*
 * Sigadd - wrapper for the sigadd function
 */
int Sigaddset(sigset_t *set, int signum){
  int status;

  if((status = sigaddset(set, signum)) < 0)
    unix_error("Sigaddset error");
  return status;
}

/*
 * Sigdelset - wrapper for the sigdelset function
 */
int Sigdelset(sigset_t *set, int signum){
  int status;

  if((status = sigdelset(set, signum)) < 0)
    unix_error("Sigdelset error");
  return status;
}

/*
 * Sigprocmask - wrapper for the sigprocmask function
 */
int Sigprocmask(int how, const sigset_t *set, sigset_t *oset){
  int status;

  if((status = sigprocmask(how, set, oset)) < 0)
    unix_error("Sigprocmask error");
  return status;
}

/*
 * Sigsuspend - wrapper for the sigsuspend function
 */
int Sigsuspend(const sigset_t *sigmask){
  int status;

  if(((status = sigsuspend(sigmask)) < 0) && (errno != EINTR)) /* ignore system call interruption error to restart */
    unix_error("Sigsuspend error");
  return status;
}
