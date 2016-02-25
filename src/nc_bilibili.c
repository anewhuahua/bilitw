/*
 * refacture to let tw support multiple process under multi-core arch
 *
 * nc_bilibili is master process
 *
 * Main functionality:
 * 	Initialize tw worker process
 *	Dispatch signal
 *	Handle user input
 *
 * Todo:
 * 	Hot reload configuration
 *	Graceful restart
 *
 * twemproxy - A fast and lightweight proxy for memcached protocol.
 * Copyright (C) 2011 Twitter, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include <nc_core.h>
#include <nc_conf.h>


#define NC_CONF_PATH        "/etc/nutcracker.yml"

#define NC_LOG_DEFAULT      LOG_NOTICE
#define NC_LOG_MIN          LOG_EMERG
#define NC_LOG_MAX          LOG_PVERB
#define NC_LOG_PATH         NULL

#define NC_STATS_PORT       STATS_PORT
#define NC_STATS_ADDR       STATS_ADDR
#define NC_STATS_INTERVAL   STATS_INTERVAL

#define NC_PID_FILE         NULL

#define NC_MBUF_SIZE        MBUF_SIZE
#define NC_MBUF_MIN_SIZE    MBUF_MIN_SIZE
#define NC_MBUF_MAX_SIZE    MBUF_MAX_SIZE

static int show_help;
static int show_version;
static int test_conf;
static int daemonize;
static int describe_stats;
struct instance nci_global;
struct env_master env_global;


int  nc_reap;
int  nc_sigio;
int  nc_sigalarm;
int  nc_terminate;
int	 nc_quit;
//
int  nc_reload;
int  nc_reload_start;
int  nc_cnt_reload;
int  nc_debug_quit;
int  nc_exiting;
int  nc_reopen;
int  nc_daemonized;
int  nc_get_stats_cmd;
int  nc_stats_listen_sd;

int  nc_noaccept;
int  nc_noaccepting;
int  nc_restart;
nc_pid_t  nc_pid;




static struct option long_options[] = {
    { "help",           no_argument,        NULL,   'h' },
    { "version",        no_argument,        NULL,   'V' },
    { "daemonize",      no_argument,        NULL,   'd' },
    { "describe-stats",  no_argument,        NULL,   'D' },
	{ "test-conf",      required_argument,  NULL,   't' },
    { "verbose",        required_argument,  NULL,   'v' },
    { "output",         required_argument,  NULL,   'o' },
    { "conf-file",      required_argument,  NULL,   'c' },
    { "stats-port",     required_argument,  NULL,   's' },
    { "stats-interval", required_argument,  NULL,   'i' },
    { "stats-addr",     required_argument,  NULL,   'a' },
    { "pid-file",       required_argument,  NULL,   'p' },
    { "mbuf-size",      required_argument,  NULL,   'm' },
	{"worker-num",      required_argument,  NULL,   'n' },
	{"core-mask",       required_argument,  NULL,   'M' },
    { NULL,             0,                  NULL,    0 }
};

static char short_options[] = "hVdDt:v:o:c:s:i:a:p:m:n:M:";
static char  master_process[] = "bilibili tw master process";
static char* log_filename_global;
static char* conf_filename_global;

extern char **environ;
static char *nc_os_argv_last;
extern int             nc_argc;
extern char           **nc_argv;
extern char           **nc_os_argv;


static fd_set rdfs;
static int fds_width;

static void addfs(s) {
    if (s > fds_width) {
		fds_width = s;
	} 
	FD_SET(s, &rdfs); 
}
static void
rebuild_fdset(void)
{	
	int i;
	fds_width = 0;
	FD_ZERO(&rdfs);
	for (i = 0; i < nc_last_process; i++) {
		if (nc_processes[i].pid == -1 || nc_processes[i].pid == 0){
			continue;
		}
		addfs(nc_processes[i].channel[0]);
	}
	fds_width++;
}


void nc_start_worker_processes(struct env_master* env);


u_char *
nc_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) {
        return dst;
    }

    while (--n) {
        *dst = *src;

        if (*dst == '\0') {
            return dst;
        }

        dst++;
        src++;
    }

    *dst = '\0';

    return dst;
}
static int
nc_save_argv(int argc, char *const *argv)
{

    size_t     len;
    int  i;

    nc_os_argv = (char **) argv;
    nc_argc = argc;
    nc_argv = malloc((argc + 1) * sizeof(char *));
    if (nc_argv == NULL) {
        return NC_ERROR;
    }

    for (i = 0; i < argc; i++) {
        len = nc_strlen(argv[i]) + 1;

        nc_argv[i] = malloc(len);
        if (nc_argv[i] == NULL) {
            return NC_ERROR;
        }

        (void) nc_cpystrn((u_char *) nc_argv[i], (u_char *) argv[i], len);
    }

    nc_argv[i] = NULL;
    //nc_os_environ = environ;
    return NC_OK;
}

int
nc_init_setproctitle()
{
    unsigned char *p;
    size_t       size;
    int   i;
    size = 0;

    for (i = 0; environ[i]; i++) {
        size += strlen(environ[i]) + 1;
    }

    p = malloc(size);
    if (p == NULL) {
		log_error("malloc process title error: %s", strerror(errno));
        return NC_ERROR;
    }

    nc_os_argv_last = nc_os_argv[0];

    for (i = 0; nc_os_argv[i]; i++) {
        if (nc_os_argv_last == nc_os_argv[i]) {
            nc_os_argv_last = nc_os_argv[i] + strlen(nc_os_argv[i]) + 1;
        }
    }

    for (i = 0; environ[i]; i++) {
        if (nc_os_argv_last == environ[i]) {

            size = strlen(environ[i]) + 1;
            nc_os_argv_last = environ[i] + size;

            nc_cpystrn(p, (u_char *) environ[i], size);
            environ[i] = (char *) p;
            p += size;
        }
    }

    nc_os_argv_last--;

    return NC_OK;
}


void
nc_setproctitle(char *title)
{
    u_char     *p;
    nc_os_argv[1] = NULL;
    p = nc_cpystrn((u_char *) nc_os_argv[0], (u_char *) "bilitw ",
                    nc_os_argv_last - nc_os_argv[0]);

    p = nc_cpystrn(p, (u_char *) title, nc_os_argv_last - (char *) p);

    if (nc_os_argv_last - (char *) p) {
        memset(p, '\0', nc_os_argv_last - (char *) p);
    }
    log_error("setproctitle: \"%s\"", nc_os_argv[0]);
}






static rstatus_t
nc_daemonize(int dump_core)
{
    rstatus_t status;
    pid_t pid, sid;
    int fd;

    pid = fork();
    switch (pid) {
    case -1:
        log_error("fork() failed: %s", strerror(errno));
        return NC_ERROR;

    case 0:
        break;

    default:
        /* parent terminates */
        _exit(0);
    }

    /* 1st child continues and becomes the session leader */

    sid = setsid();
    if (sid < 0) {
        log_error("setsid() failed: %s", strerror(errno));
        return NC_ERROR;
    }
    // ignore sighup at this place
    if (signal(SIGHUP, SIG_IGN) == SIG_ERR) {
        log_error("signal(SIGHUP, SIG_IGN) failed: %s", strerror(errno));
        return NC_ERROR;
    }

    pid = fork();
    switch (pid) {
    case -1:
        log_error("fork() failed: %s", strerror(errno));
        return NC_ERROR;

    case 0:
        break;

    default:
        /* 1st child terminates */
        _exit(0);
    }

    /* 2nd child continues */

    /* change working directory */
    if (dump_core == 0) {
        status = chdir("/");
        if (status < 0) {
            log_error("chdir(\"/\") failed: %s", strerror(errno));
            return NC_ERROR;
        }
    }

    /* clear file mode creation mask */
    umask(0);

    /* redirect stdin, stdout and stderr to "/dev/null" */

    fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        log_error("open(\"/dev/null\") failed: %s", strerror(errno));
        return NC_ERROR;
    }

    status = dup2(fd, STDIN_FILENO);
    if (status < 0) {
        log_error("dup2(%d, STDIN) failed: %s", fd, strerror(errno));
        close(fd);
        return NC_ERROR;
    }

    status = dup2(fd, STDOUT_FILENO);
    if (status < 0) {
        log_error("dup2(%d, STDOUT) failed: %s", fd, strerror(errno));
        close(fd);
        return NC_ERROR;
    }

    status = dup2(fd, STDERR_FILENO);
    if (status < 0) {
        log_error("dup2(%d, STDERR) failed: %s", fd, strerror(errno));
        close(fd);
        return NC_ERROR;
    }

    if (fd > STDERR_FILENO) {
        status = close(fd);
        if (status < 0) {
            log_error("close(%d) failed: %s", fd, strerror(errno));
            return NC_ERROR;
        }
    }

    return NC_OK;
}

static void
nc_print_run(struct env_master *env)
{
    int status;
    struct utsname name;

    status = uname(&name);
    if (status < 0) {
        loga("nutcracker-%s master started on pid %d", NC_VERSION_STRING, env->pid);
    } else {
        loga("nutcracker-%s master built for %s %s %s started on pid %d",
             NC_VERSION_STRING, name.sysname, name.release, name.machine,
             env->pid);
    }

    loga("run, rabbit run / dig that hole, forget the sun / "
         "and when at last the work is done / don't sit down / "
         "it's time to dig another one");
}

static void
nc_print_done(void)
{
    loga("done, rabbit done");
}

static void
nc_show_usage(void)
{
    log_stderr(
        "Usage: nutcracker [-?hVdDt] [-v verbosity level] [-o output file]" CRLF
        "                  [-c conf file] [-s stats port] [-a stats addr]" CRLF
        "                  [-i stats interval] [-p pid file] [-m mbuf size]" CRLF
        "");
	
    log_stderr(
        "Options:" CRLF
        "  -h, --help             : this help" CRLF
        "  -V, --version          : show version and exit" CRLF
        "  -t, --test-conf        : test configuration for syntax errors and exit" CRLF
        "  -d, --daemonize        : run as a daemon" CRLF
        "  -D, --describe-stats   : print stats description and exit");
    log_stderr(
        "  -v, --verbose=N        : set logging level (default: %d, min: %d, max: %d)" CRLF
        "  -o, --output=S         : set logging file (default: %s)" CRLF
        "  -c, --conf-file=S      : set configuration file (default: %s)" CRLF
        "  -s, --stats-port=N     : set stats monitoring port (default: %d)" CRLF
        "  -a, --stats-addr=S     : set stats monitoring ip (default: %s)" CRLF
        "  -i, --stats-interval=N : set stats aggregation interval in msec (default: %d msec)" CRLF
        "  -p, --pid-file=S       : set pid file (default: %s)" CRLF
        "  -m, --mbuf-size=N      : set size of mbuf chunk in bytes (default: %d bytes)" CRLF
		"  -n, --worker-num=N     : set number of workers (default: number of cpu cores)" CRLF
		"  -M, --core-mask=N	  : set cpu core mask that worker process bind to" CRLF
        "",
        NC_LOG_DEFAULT, NC_LOG_MIN, NC_LOG_MAX,
        NC_LOG_PATH != NULL ? NC_LOG_PATH : "stderr",
        NC_CONF_PATH,
        NC_STATS_PORT, NC_STATS_ADDR, NC_STATS_INTERVAL,
        NC_PID_FILE != NULL ? NC_PID_FILE : "off",
        NC_MBUF_SIZE);
}

static void
nc_remove_pidfile(struct instance *nci)
{
    int status;

    status = unlink(nci->pid_filename);
    if (status < 0) {
        log_error("unlink of pid file '%s' failed, ignored: %s",
                  nci->pid_filename, strerror(errno));
    }
}

static rstatus_t
nc_create_pidfile(struct env_master *env)
{
    char pid[NC_UINTMAX_MAXLEN];
    int fd, pid_len;
    ssize_t n;

    fd = open(env->pid_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        log_error("opening pid file '%s' failed: %s", env->pid_filename,
                  strerror(errno));
        return NC_ERROR;
    }
    env->pidfile = 1;

    pid_len = nc_snprintf(pid, NC_UINTMAX_MAXLEN, "%d", env->pid);

    n = nc_write(fd, pid, pid_len);
    if (n < 0) {
        log_error("write to pid file '%s' failed: %s", env->pid_filename,
                  strerror(errno));
        return NC_ERROR;
    }

    close(fd);

    return NC_OK;
}

static void
nc_remove_master_pidfile(struct env_master *env)
{
    int status;

    status = unlink(env->pid_filename);
    if (status < 0) {
        log_error("unlink of pid file '%s' failed, ignored: %s",
                  env->pid_filename, strerror(errno));
    }
}

static void
nc_set_default_options(struct env_master *env)
{
    int status;

    env->ctx = NULL;

    env->log_level = NC_LOG_DEFAULT;
    env->log_filename = NC_LOG_PATH;

    env->conf_filename = NC_CONF_PATH;

    env->stats_port = NC_STATS_PORT;
    env->stats_addr = NC_STATS_ADDR;
    env->stats_interval = NC_STATS_INTERVAL;

	env->stats_duration = NC_STATS_INTERVAL * 10;	// every 5 mins
	env->reload_timeout = 1000 * 120;				// 2 mins for reload timeout
	env->slow_req_duration = CONF_UNSET_NUM;

    status = nc_gethostname(env->hostname, NC_MAXHOSTNAMELEN);
    if (status < 0) {
        log_warn("gethostname failed, ignored: %s", strerror(errno));
        nc_snprintf(env->hostname, NC_MAXHOSTNAMELEN, "unknown");
    }
    env->hostname[NC_MAXHOSTNAMELEN - 1] = '\0';

    env->mbuf_chunk_size = NC_MBUF_SIZE;

    env->pid = (pid_t)-1;
    env->pid_filename = NULL;
    env->pidfile = 0;
}

static rstatus_t
nc_get_options(int argc, char **argv, struct env_master *env)
{
    int c, value;
	int len;
	uint64_t cores;
	uint64_t value1;

    opterr = 0;
	//ASSERT(0);
	
    for (;;) {
        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            /* no more options */
            break;
        }

        switch (c) {
        case 'h':
            show_version = 1;
            show_help = 1;
            break;

        case 'V':
            show_version = 1;
            break;

        case 't':
            test_conf = 1;
			env->conf_filename = optarg;
            break;

        case 'd':
            daemonize = 1;
            break;

        case 'D':
            describe_stats = 1;
            show_version = 1;
            break;

        case 'v':
            value = nc_atoi(optarg, strlen(optarg));
            if (value < 0) {
                log_stderr("nutcracker: option -v requires a number");
                return NC_ERROR;
            }
            env->log_level = value;
            break;

        case 'o':
            env->log_filename = optarg;
			len = nc_strlen(optarg) + 1;
        	log_filename_global = malloc(len);
	        if (log_filename_global == NULL) {
	            return NC_ERROR;
	        }
            nc_cpystrn((u_char *) log_filename_global, (u_char *) optarg, len);
            break;

        case 'c':
            env->conf_filename = optarg;
			len = nc_strlen(optarg) + 1;
        	conf_filename_global = malloc(len);
	        if (conf_filename_global == NULL) {
	            return NC_ERROR;
	        }
            nc_cpystrn((u_char *) conf_filename_global, (u_char *) optarg, len);
			break;

        case 's':
            value = nc_atoi(optarg, strlen(optarg));
            if (value < 0) {
                log_stderr("nutcracker: option -s requires a number");
                return NC_ERROR;
            }
            if (!nc_valid_port(value)) {
                log_stderr("nutcracker: option -s value %d is not a valid "
                           "port", value);
                return NC_ERROR;
            }

            env->stats_port = (uint16_t)value;
            break;

        case 'i':
            value = nc_atoi(optarg, strlen(optarg));
            if (value < 0) {
                log_stderr("nutcracker: option -i requires a number");
                return NC_ERROR;
            }

            env->stats_interval = value;
            break;

        case 'a':
            env->stats_addr = optarg;
            break;

        case 'p':
            env->pid_filename = optarg;
            break;

        case 'm':
            value = nc_atoi(optarg, strlen(optarg));
            if (value <= 0) {
                log_stderr("nutcracker: option -m requires a non-zero number");
                return NC_ERROR;
            }

            if (value < NC_MBUF_MIN_SIZE || value > NC_MBUF_MAX_SIZE) {
                log_stderr("nutcracker: mbuf chunk size must be between %zu and" \
                           " %zu bytes", NC_MBUF_MIN_SIZE, NC_MBUF_MAX_SIZE);
                return NC_ERROR;
            }

            env->mbuf_chunk_size = (size_t)value;
            break;

		case 'n':
			value = nc_atoi(optarg, strlen(optarg));
            if (value <= 0) {
                log_stderr("nutcracker: option -n requires a non-zero number");
                return NC_ERROR;
            }
			
			cores = sysconf(_SC_NPROCESSORS_ONLN);
			
            if (value > cores || value < 1) {
                log_stderr("bilitw: bilitw worker process number should be between %d and" \
                           " %d", 1, cores);
                return NC_ERROR;
            }
            env->worker_processes= value;			
			break;
		case 'M':
			value1 = nc_atoi(optarg, strlen(optarg));
            if (value1 <= 0) {
                log_stderr("nutcracker: option -M requires a non-zero number");
                return NC_ERROR;
            }
			cores = sysconf(_SC_NPROCESSORS_ONLN);
			cores = (1LL<<cores) -1;

            if (value1 > cores || value1 < 1) {
                log_stderr("bilitw: bilitw worker process cpu mask should be set between %d and" \
                           " %d", 1, cores);
                return NC_ERROR;
            } 
			env->cpu_mask = value1;
			break;

        case '?':
            switch (optopt) {
            case 'o':
            case 'c':
            case 'p':
                log_stderr("nutcracker: option -%c requires a file name",
                           optopt);
                break;

            case 'm':
            case 'v':
            case 's':
            case 'i':
			case 'n':
			case 'M':
                log_stderr("nutcracker: option -%c requires a number", optopt);
                break;

            case 'a':
                log_stderr("nutcracker: option -%c requires a string", optopt);
                break;

            default:
                log_stderr("nutcracker: invalid option -- '%c'", optopt);
                break;
            }
            return NC_ERROR;

        default:
            log_stderr("nutcracker: invalid option -- '%c'", optopt);
            return NC_ERROR;

        }
    }

    return NC_OK;
}

/*
 * Returns true if configuration file has a valid syntax, otherwise
 * returns false
 */
static bool
nc_test_conf(struct env_master *env)
{
    struct conf *cf;

    cf = conf_create(env->conf_filename);
    if (cf == NULL) {
        log_stderr("nutcracker: configuration file '%s' syntax is invalid",
                   env->conf_filename);
        return false;
    }

    conf_destroy(cf);

    log_stderr("nutcracker: configuration file '%s' syntax is ok",
               env->conf_filename);
    return true;
}



static rstatus_t
nc_master_pre_run(struct env_master *env)
{
    rstatus_t status;

    status = log_init(env->log_level, env->log_filename);
    if (status != NC_OK) {
        return status;
    }
    // master run as daemon process. belong to INIT process
	// daemonize = 0;  

    if (daemonize) {
        status = nc_daemonize(1);
        if (status != NC_OK) {
            return status;
        }
    }

	

    env->pid = getpid();
	
    // init the signalling handler
    status = signal_init();
    if (status != NC_OK) {
        return status;
    }

    if (env->pid_filename) {
        status = nc_create_pidfile(env);
        if (status != NC_OK) {
            return status;
        }
    }

    nc_print_run(env);

    return NC_OK;
}


static rstatus_t
nc_worker_pre_run(struct instance *nci)
{
    rstatus_t status;

    status = log_init(nci->log_level, nci->log_filename);
    if (status != NC_OK) {
        return status;
    }

	/*
    if (daemonize) {
        status = nc_daemonize(1);
        if (status != NC_OK) {
            return status;
        }
    }*/

    nci->pid = getpid();

	/*
    status = signal_init();
    if (status != NC_OK) {
        return status;
    }
	*/
	/*
    if (nci->pid_filename) {
        status = nc_create_pidfile(nci);
        if (status != NC_OK) {
            return status;
        }
    }*/

    /*nc_print_run(nci);*/

    return NC_OK;
}


static void
nc_master_post_run(struct env_master *env)
{
   // kill all the children process.


    if (env->pidfile) {
        nc_remove_master_pidfile(env);
    }

    signal_deinit();

    nc_print_done();

    log_deinit();
}


static void
nc_worker_post_run(struct instance *nci)
{
    if (nci->pidfile) {
        nc_remove_pidfile(nci);
    }

    signal_deinit();

    nc_print_done();

    log_deinit();
}

static void
nc_run(struct instance *nci)
{
    rstatus_t status;
    struct context *ctx;

    ctx = core_start(nci);
    if (ctx == NULL) {
        return;
    }

    /* run rabbit run */
    for (;;) {
        status = core_loop(ctx);
        if (status != NC_OK) {
            break;
        }
    }

    core_stop(ctx);
}

void
tw_worker_cycle(void *data)
{
    rstatus_t status;
	pid_t pid;
	char tmp_name[100];
	int i;
	sigset_t		  set;

	
	nc_process_role = NC_PROCESS_WORKER;
	sprintf(tmp_name, "worker %d", nc_worker_index);
	nc_setproctitle(tmp_name);
	
	// done by slave to replace master signal !important
	sigemptyset(&set);
	if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
		log_error("sigprocmask() children %d failed", nc_worker_index);
	}

    //nc_set_default_options(&env_global);
    //status = nc_get_options(nc_argc, nc_argv, &env_global);
    //if (status != NC_OK) {
    //    exit(1);
    //}
	//memcpy(&nci_global, &env_global, sizeof(struct instance));
 
	if (conf_filename_global==NULL){
		nci_global.conf_filename = NC_CONF_PATH;	
	} else {
		nci_global.conf_filename = conf_filename_global;
	}
	if (log_filename_global == NULL) {
		nci_global.log_filename = NC_LOG_PATH;
	} else {
		nci_global.log_filename = log_filename_global;
	}
	log_error("%s", nci_global.conf_filename);

	pid = getpid();
	//CPU_ZERO(&cpu_mask);
    //CPU_SET(nc_worker_index, &cpu_mask);
	for (i = 0; i < sysconf(_SC_NPROCESSORS_ONLN); i++ ) {
	  if (CPU_ISSET(i, &cpu_mask)){
	    break;
	  }
	}
    if(sched_setaffinity(pid, sizeof(cpu_set_t), &cpu_mask) == -1) {
      log_error("warning: worker %d bind process pid %d on cpu%d fail\n", nc_worker_index, pid, i);
    }else{
      log_error("worker %d bind current process pid %d to core %d\n", nc_worker_index, pid, i);
    }
	log_error("process pid %d socketpair channel %d", pid, nc_worker_channel);
	  
    status = nc_worker_pre_run(&nci_global);
    if (status != NC_OK) {
        nc_worker_post_run(&nci_global);
        exit(1);
    }

    nc_run(&nci_global);

    nc_worker_post_run(&nci_global);

    exit(1);
}




void
tw_master_cycle(struct env_master* env)
{   
    int         sigio;
    sigset_t           set;
    struct itimerval   itv;
    unsigned int       live;

	// msec: 1/1000 sec
    unsigned int       delay;
	int i, r;
	struct timeval tv;
   

	nc_process_role = NC_PROCESS_MASTER;
	nc_setproctitle("master");

    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGINT);
    //reconfigure
    sigaddset(&set, SIGHUP);  
    // noaccept
    sigaddset(&set, SIGWINCH);
	
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGQUIT);
	
    //sigaddset(&set, ngx_signal_value(NGX_CHANGEBIN_SIGNAL));
    //sigaddset(&set, ngx_signal_value(NGX_REOPEN_SIGNAL));


    // block above singalling
    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        log_error("sigprocmask() failed %s", strerror(errno));
    }
    sigemptyset(&set);

    nc_start_worker_processes(env);
	stats_master_server(env->stats_port, env->stats_addr);


    // master
    //delay = 1000;
	delay = 1; // 1ms
    sigio = 0;
    live = 1;
	nc_reload_start = 0;

    for ( ;; ) {
        // no singal, alarm event
        if (nc_sigalarm) {	 
        	sigio = 0;
		   	// like slow start
            // delay *= 2;			
            nc_sigalarm= 0;
	
			if (nc_reload_start) {
				rebuild_fdset();
				tv.tv_sec = 0;
				tv.tv_usec = 0;
				//log_error("tyson, %d", fds_width);
				r = select(fds_width, &rdfs, NULL, NULL, &tv);
				if (r) {
					for (i = 0; i < fds_width; i++) {
						if (FD_ISSET(i, &rdfs)){
							nc_read_channel(i, &env_global.ctrl_msg, sizeof(nc_channel_msg_t));
						}	
					}
				}
			}
			
			/*
			for (i = 0; i < nc_last_process; i++) {
				if (nc_processes[i].pid == -1 || nc_processes[i].pid == 0){
					continue;
				}

				
				//log_debug(LOG_ERR, "tyson here");
				nc_read_channel(nc_processes[0].channel_back[0], &env_global.ctrl_msg, sizeof(nc_channel_msg_t));
				//nc_read_channel(nc_processes[i].channel[1], &env_global.ctrl_msg, sizeof(nc_channel_msg_t));
			}*/

			
			if (nc_reload_start && !nc_cnt_reload) {
				nc_reload_start = 0;
				nc_cnt_reload = NC_CNT_RELOAD_MAGIC;
			}
         }

        log_debug("termination cycle: %d", delay);

        itv.it_interval.tv_sec = 0;
        itv.it_interval.tv_usec = 0;
        itv.it_value.tv_sec = delay / 1000;
        itv.it_value.tv_usec = (delay % 1000 ) * 1000;
	    // produce SIGALARM
        if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
        	log_debug("setitimer() failed %s", strerror(errno));
        }
	
        //log_debug("sigsuspend");
        sigsuspend(&set);
		// wake up this place
        log_debug("wake up, sigio %d", sigio);
    	 
        if (nc_reap) {
            nc_reap = 0;
            log_warn("reap children");
			
            live = nc_reap_children();
        }
	 
		// best effort, send signal via channel before death
        // if (!live && (nc_terminate || nc_quit)) {
		if (nc_terminate) {
			nc_term_children();
			sleep(1);
            nc_master_post_run(env);
	     	exit(1);
        }
		
        if (nc_terminate) {
            if (delay == 0) {
                delay = 50;
            }

            if (sigio) {
                sigio--;
                continue;
            }

            sigio = env->worker_processes;
	        // kill -9
            if (delay > 2000) {		
                nc_signal_worker_processes(SIGKILL);
            } else {
                nc_signal_worker_processes(SIGTERM);
            }

            continue;
        }

		// graceful shutdown
        if (nc_quit) {
            nc_signal_worker_processes(SIGQUIT);                 
			/*
            ls = cycle->listening.elts;
            for (n = 0; n < cycle->listening.nelts; n++) {
                if (ngx_close_socket(ls[n].fd) == -1) {
                    ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                                  ngx_close_socket_n " %V failed",
                                  &ls[n].addr_text);
                }
            }
            cycle->listening.nelts = 0;
            */

            continue;
        }

		// todo
		/*
        if (nc_restart) {
            nc_restart = 0;
            nc_start_worker_processes(env);
            live = 1;
        }
		*/
#ifdef GRACEFUL
		if (nc_reload && !nc_reload_start) {
			nc_reload = 0;  
			nc_reload_start = 1;
			nc_cnt_reload = NC_CNT_RELOAD_MAGIC;
			//reset after all worker processes reload done
			nc_signal_worker_processes(SIGHUP);
			continue;
		} else if (nc_reload) {
			log_debug(LOG_ERR, "deny reload request due to reason: still in reconfiguation status %d", nc_reload_start);
		}
#endif

    }
}



rstatus_t
tw_master_conf_init(struct array *server_pool, struct array *conf_pool)
{
    rstatus_t status;
    uint32_t npool;

    npool = array_n(conf_pool);
    ASSERT(npool != 0);
    ASSERT(array_n(server_pool) == 0);

    status = array_init(server_pool, npool, sizeof(struct server_pool));
    if (status != NC_OK) {
        return status;
    }

    /* transform conf pool to server pool */
    status = array_each(conf_pool, conf_pool_master, server_pool);
    if (status != NC_OK) {
        //server_pool_deinit(server_pool);
        return status;
    }
    ASSERT(array_n(server_pool) == npool);


    return NC_OK;
}



int main(int argc, char **argv) 
{
    rstatus_t status;
	int i, count;

    //argv [0] = 'master';

	if (nc_save_argv(argc, argv) != NC_OK) {
		exit(1);
	}

    nc_set_default_options(&env_global);
	env_global.worker_processes = sysconf(_SC_NPROCESSORS_ONLN); 
	env_global.cpu_mask = (0x1LL<<env_global.worker_processes) - 1;

    status = nc_get_options(nc_argc, nc_argv, &env_global);
    if (status != NC_OK) {
        nc_show_usage();
         exit(1);
    }

	

    if (show_version) {
        log_stderr("This is nutcracker-%s" CRLF, NC_VERSION_STRING);
        if (show_help) {
            nc_show_usage();
        }

        if (describe_stats) {
            stats_describe();
        }

        exit(0);
    }

     if (test_conf) {
        if (!nc_test_conf(&env_global)) {
            exit(1);
         }
         exit(0);
     }
	 
	 memcpy(&nci_global, &env_global, sizeof(struct instance));   
	 // context will be initialized in later nc_run.
	 
	 if (nc_init_setproctitle() != NC_OK) {
        exit(1);
     }

	
     status = nc_master_pre_run(&env_global);
     if (status != NC_OK) {
        nc_master_post_run(&env_global);
        exit(1);
     }
	
	count = 0;
	for(i = 0; i<sysconf(_SC_NPROCESSORS_ONLN); i++) {
		count+= env_global.cpu_mask & (0x1LL<<i)?1:0;
		//log_error("count %d", count);
	}
	if (count < env_global.worker_processes) {
		log_error('cpu mask %x is not fit in worker processes %d', env_global.cpu_mask, env_global.worker_processes);
		nc_master_post_run(&env_global);
		exit(1);
	}

	
     /* parse and create configuration for master */
     struct conf* cf = malloc(sizeof(struct conf));
	 memset(cf, 0, sizeof(struct conf));
     cf = conf_create(env_global.conf_filename);
     if (status != NC_OK) {
        conf_destroy(cf);
        exit(1);
     } 
	 
	 if (cf->stats_duration)
	 	env_global.stats_duration = cf->stats_duration;
	 if (cf->reload_timeout)
	 	env_global.reload_timeout = cf->reload_timeout;
	 if (cf->slow_req_duration)
	 	env_global.slow_req_duration = cf->slow_req_duration;
	

     /* initialize server pool from configuration */
     status = tw_master_conf_init(&env_global.pool, &cf->pool);
     if (status != NC_OK) {
        conf_destroy(cf);
		// release array server pool
        exit(1);
     } 
	 
	 
     tw_master_cycle(&env_global);   
     nc_master_post_run(&env_global);
     exit(1);
}

