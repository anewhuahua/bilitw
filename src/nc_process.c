#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/ioctl.h>


#include <nc_core.h>
#include <sys/prctl.h>

#include <signal.h>



typedef struct {
    int     signo;
    char   *signame;
    char   *name;
    void  (*handler)(int signo);
} nc_signal_t;



int             nc_argc;
char           **nc_argv;
char           **nc_os_argv;

int                 nc_process_slot;
					// channel for read in TW workder process
int                 nc_worker_channel;
int 				nc_worker_channel_write;

int                 nc_last_process;
nc_process_t        nc_processes[NC_MAX_PROCESSES];
int				    nc_process_role;
int					nc_worker_index;
cpu_set_t 			cpu_mask;
int					cpu_mask_group[NC_MAX_PROCESSES];



// listen, accpet client connection
rstatus_t
tw_master_listen(int family, struct sockaddr* addr, socklen_t addrlen, int backlog)
{
    rstatus_t status;
	int reuse;
	socklen_t len;
	int sd;

    sd = socket(family, SOCK_STREAM, 0);
    if (sd < 0) {
        log_error("socket failed: %s", strerror(errno));
        return NC_ERROR;
    }
	// reuse addr
    reuse = 1;
    len = sizeof(reuse);
    status = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &reuse, len);
	if (status < 0) {
        log_error("reuse of addr failed: %s",
                  strerror(errno));
        return NC_ERROR;
	}
	// get rid of thundering herd
	status = setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &reuse, len);
	if (status < 0) {
        log_error("reuse of port failed: %s",
                  strerror(errno));
        return NC_ERROR;
    }

    status = bind(sd, addr, addrlen);
    if (status < 0) {
        log_error("bind on p %d: %s",sd, strerror(errno));
        return NC_ERROR;
    }

    status = listen(sd, backlog);
    if (status < 0) {
        log_error("listen on p %d failed: %s",sd,
                  sd, strerror(errno));
        return NC_ERROR;
    }

    status = nc_set_nonblocking(sd);
    if (status < 0) {
        log_error("set nonblock on p", strerror(errno));
        return NC_ERROR;
    }

	return sd;
}




nc_pid_t
nc_spawn_process( nc_spawn_proc_pt proc, int data,
    char *name, int reload)
{
    unsigned long    on;
    nc_pid_t  pid;
    int  s;
	/*
    if (respawn >= 0) {
		//s = respawn;
		
    } else {
        for (s = 0; s < nc_last_process; s++) {
            if (nc_processes[s].pid == -1) {
                break;
            }
        }

        if (s == NC_MAX_PROCESSES) {
           log_error("no more than %d processes can be spawned",
              NC_MAX_PROCESSES);
            return NC_INVALID_PID;
        }
    }*/

	for (s = 0; s < nc_last_process; s++) {
    	if (nc_processes[s].pid == -1) {
        	break;
        }
    }
    if (s == NC_MAX_PROCESSES) {
        log_error("no more than %d processes can be spawned",
           NC_MAX_PROCESSES);
        return NC_INVALID_PID;
    }
	

// Master to Worker	
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, nc_processes[s].channel) == -1)
    {
        log_error("socketpair() failed while spawning \"%s\"", name);
        return NC_INVALID_PID;
    }
    log_debug(LOG_DEBUG,  "channel %d:%d",  nc_processes[s].channel[0],  nc_processes[s].channel[1]);

    if (nc_set_nonblocking(nc_processes[s].channel[0]) < 0) {
        log_error("set channel %d nonblock failed while spawning %s: %s", 
            nc_processes[s].channel[0] , name, strerror(errno));

        nc_close_channel(nc_processes[s].channel);
        return NC_INVALID_PID;
    }

    if (nc_set_nonblocking(nc_processes[s].channel[1]) < 0) {
        log_error("set channel %d nonblock failed while spawning %s: %s", 
            nc_processes[s].channel[1] , name, strerror(errno));

        nc_close_channel(nc_processes[s].channel);
        return NC_INVALID_PID;
    }
	/*
    on = 1;
    if (ioctl(nc_processes[s].channel[0], FIOASYNC, &on) == -1) {
        log_error("set channel %d FIOASYNC failed while spawning %s: %s", 
            nc_processes[s].channel[0] , name, strerror(errno));
        nc_close_channel(nc_processes[s].channel);
        return NC_INVALID_PID;
    }*/
	
	nc_pid = getpid();
    if (fcntl(nc_processes[s].channel[0], F_SETOWN, nc_pid) == -1) {
        log_error("set channel %d F_SETOWN failed while spawning %s: %s", 
            nc_processes[s].channel[0] , name, strerror(errno));
        nc_close_channel(nc_processes[s].channel);
        return NC_INVALID_PID;
    }

    if (fcntl(nc_processes[s].channel[0], F_SETFD, FD_CLOEXEC) == -1) {
        log_error("set channel %d  FD_CLOEXEC failed while spawning %s: %s", 
            nc_processes[s].channel[0] , name, strerror(errno));
        nc_close_channel(nc_processes[s].channel);
        return NC_INVALID_PID;
    }

    if (fcntl(nc_processes[s].channel[1], F_SETFD, FD_CLOEXEC) == -1) {
        log_error("set channel %d FD_CLOEXEC failed while spawning %s: %s", 
            nc_processes[s].channel[1] , name, strerror(errno));
        nc_close_channel(nc_processes[s].channel);
        return NC_INVALID_PID;
    }

// Worker to Master
	/*
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, nc_processes[s].channel_back) == -1)
    {
        log_error("socketpair() failed while spawning \"%s\"", name);
        return NC_INVALID_PID;
    }
    log_debug(LOG_DEBUG,  "channel %d:%d", nc_processes[s].channel_back[0], nc_processes[s].channel_back[1]);

	
    if (nc_set_nonblocking(nc_processes[s].channel_back[0]) < 0) {
        log_error("set channel %d nonblock failed while spawning %s: %s", 
            nc_processes[s].channel_back[0] , name, strerror(errno));

        nc_close_channel(nc_processes[s].channel_back);
        return NC_INVALID_PID;
    }

    if (nc_set_nonblocking(nc_processes[s].channel_back[1]) < 0) {
        log_error("set channel %d nonblock failed while spawning %s: %s", 
            nc_processes[s].channel_back[1] , name, strerror(errno));

        nc_close_channel(nc_processes[s].channel_back);
        return NC_INVALID_PID;
    }
   
	nc_pid = getpid();
    if (fcntl(nc_processes[s].channel_back[0], F_SETOWN, nc_pid) == -1) {
        log_error("set channel %d F_SETOWN failed while spawning %s: %s", 
            nc_processes[s].channel_back[0] , name, strerror(errno));
        nc_close_channel(nc_processes[s].channel_back);
        return NC_INVALID_PID;
    }

    if (fcntl(nc_processes[s].channel_back[0], F_SETFD, FD_CLOEXEC) == -1) {
        log_error("set channel %d  FD_CLOEXEC failed while spawning %s: %s", 
            nc_processes[s].channel_back[0] , name, strerror(errno));
        nc_close_channel(nc_processes[s].channel_back);
        return NC_INVALID_PID;
    }

    if (fcntl(nc_processes[s].channel_back[1], F_SETFD, FD_CLOEXEC) == -1) {
        log_error("set channel %d FD_CLOEXEC failed while spawning %s: %s", 
            nc_processes[s].channel_back[1] , name, strerror(errno));
        nc_close_channel(nc_processes[s].channel_back);
        return NC_INVALID_PID;
    }
	*/

    nc_worker_channel = nc_processes[s].channel[1];
	//nc_worker_channel_write = nc_processes[s].channel_back[1];

    //global variable
    nc_process_slot = s;
	  
    pid = fork();

    switch (pid) {

    case -1:
        log_error("fork() failed while spawning %s: %s", 
             name, strerror(errno));
        nc_close_channel(nc_processes[s].channel);
		nc_close_channel(nc_processes[s].channel_back);

        return NC_INVALID_PID;

    case 0: 
        // children
        nc_pid = getpid();
		close(nc_processes[s].channel[0]);
		/*
		if (prctl( PR_SET_NAME, name, NULL, NULL, NULL)!=0) {
			log_error("set name error, %s %s", name, strerror(errno));
		} else {
			log_error("set name success, %s", name);
		}*/	
		
        proc(data);
        break;

    default:
        break;
    }

    // master
    log_debug(LOG_NOTICE,  "start %s %P",  name,  pid);
    close(nc_processes[s].channel[1]);
    nc_processes[s].pid = pid;
    nc_processes[s].exited = 0;
	nc_processes[s].isNew = 1;
	nc_processes[s].idxWorker = data;

    nc_processes[s].proc = proc;
    //nc_processes[s].data = data;
    nc_processes[s].name = name;
    nc_processes[s].exiting = 0;

    if (s == nc_last_process) {
        nc_last_process++;
    }

    return pid;
}


void
nc_start_new_worker(nc_process_t* process)
{
    int i, j;
    nc_channel_msg_t  message;
	char process_name[100];
	int worker_idx;
	int cpu_idx;

    log_debug(LOG_NOTICE,  "start new worker process while reloading configuration");
    memset(&message, 0, sizeof(nc_channel_msg_t));
    message.command = NC_CMD_OPEN_CHANNEL;

	worker_idx = process->idxWorker;
	nc_worker_index = worker_idx;
	sprintf(process_name, "%s_%d", "bilitworker", i);
	
	// cpu mask
	cpu_idx = cpu_mask_group[worker_idx];
	CPU_ZERO(&cpu_mask);
	CPU_SET(cpu_idx, &cpu_mask);	
	nc_spawn_process(tw_worker_cycle,
                          worker_idx, process_name, -1);

	// master process
    message.pid = nc_processes[nc_process_slot].pid;
    message.slot = nc_process_slot;
    message.fd = nc_processes[nc_process_slot].channel[0];
    nc_pass_open_channel(&message);

}


void
nc_start_worker_processes(struct env_master* env)
{
    int i, j;
    nc_channel_msg_t  message;
	char process_name[100];

    log_debug(LOG_NOTICE,  "start worker processes");
    memset(&message, 0, sizeof(nc_channel_msg_t));
	memset(cpu_mask_group, 0, sizeof(int)*NC_MAX_PROCESSES);

    message.command = NC_CMD_OPEN_CHANNEL;

    for (i = 0; i < env->worker_processes; i++) {
		nc_worker_index = i;
		sprintf(process_name, "%s_%d", "bilitworker", i);
		
		for (j = 0; j < sysconf(_SC_NPROCESSORS_ONLN); j++) {
		  if (env->cpu_mask & (0x1LL<<j)) {
			env->cpu_mask&= ~(0x1LL<<j);
			break;
		  } 
		}
		log_error("set worker %d affinity to cpu core %d", nc_worker_index, j);
		CPU_ZERO(&cpu_mask);
    	CPU_SET(j, &cpu_mask);
		// i -> worker idx;   j -> cpu idx
		cpu_mask_group[i] = j; 
        nc_spawn_process(tw_worker_cycle,
                          i, process_name, -1);

	  	// master process
        message.pid = nc_processes[nc_process_slot].pid;
        message.slot = nc_process_slot;
        message.fd = nc_processes[nc_process_slot].channel[0];

        nc_pass_open_channel(&message);
    }
}


void
nc_process_get_status(void)
{
    int              status;
    char            *process;
    nc_pid_t        pid;
    int        err;
    int        i;
    int       one;

    one = 0;

    for ( ;; ) {
        pid = waitpid(-1, &status, WNOHANG);

        if (pid == 0) {
            return;
        }

        if (pid == -1) {
            err = errno;

            if (err == EINTR) {
                continue;
            }

            if (err == ECHILD && one) {
                return;
            }

            /*
             * Solaris always calls the signal handler for each exited process
             * despite waitpid() may be already called for this process.
             *
             * When several processes exit at the same time FreeBSD may
             * erroneously call the signal handler for exited process
             * despite waitpid() may be already called for this process.
             */

            if (err == ECHILD) {
                log_error("waitpid() failed");
                return;
            }

            log_error("waitpid() failed %s", strerror(err));
            return;
        }


        one = 1;
        process = "unknown process";

        for (i = 0; i < nc_last_process; i++) {
            if (nc_processes[i].pid == pid) {
                nc_processes[i].status = status;
                nc_processes[i].exited = 1;
             	process = nc_processes[i].name;

				// recycle the dust process
				nc_processes[i].pid = -1;
				//nc_close_channel(nc_processes[i].channel);

				nc_processes[i].channel[0] = -1;
				nc_processes[i].channel[1] = -1;

                break;
            }
        }
    }
}

/*
void nc_reply_reopen_msg()
{
	nc_channel_msg_t	 message;
	int ret;
	log_debug("replyReopnMsg");
	memset(&message, 0, sizeof(nc_channel_msg_t));
	message.command = NC_CMD_REOPEN_REPLY; 
	ret = nc_write_channel(nc_processes[i].channel[0],
							 &message, sizeof(nc_channel_msg_t));
}


void nc_waiting_reopen()
{

}
*/

