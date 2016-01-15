
#include <signal.h>
#include <nc_core.h>


int
nc_write_channel(int s, nc_channel_msg_t *message, size_t size)
{
    int             n;
    int           err;
    struct iovec        iov[1];
    struct msghdr       msg;

	memset(&msg, 0, sizeof(struct msghdr));
	memset(iov, 0, sizeof(struct iovec));

    iov[0].iov_base = (char *) message;
    iov[0].iov_len = size;
	
	msg.msg_flags = 0;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    n = sendmsg(s, &msg, 0);

    if (n == -1) {
        err = errno;
        if (err == EAGAIN) {
            return EAGAIN;
        }
	  log_debug(LOG_ALERT,  "sendmsg() failed: %s", strerror(err));
        return NC_ERROR;
    }

    return NC_OK;
}

int
nc_read_channel(int s, nc_channel_msg_t *message, size_t size)
{
    int           n;
    int           err;
	int 		  slot;
    struct iovec        iov[1];
    struct msghdr       msg;
	memset(&msg, 0, sizeof(struct msghdr));
	memset(iov, 0, sizeof(struct iovec));

    iov[0].iov_base = (char *) message;
    iov[0].iov_len = size;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
 

    n = recvmsg(s, &msg, 0);

    if (n == -1) {
        err = errno;
        if (err == EAGAIN) {
            return EAGAIN;
        }

        //log_debug(LOG_ALERT,  "recvmsg() failed %s", strerror(err));
        return NC_ERROR;
    }

    if (n == 0) {
        log_debug(LOG_DEBUG, "recvmsg() returned zero");
        return NC_ERROR;
    }

    if ((size_t) n < sizeof(nc_channel_msg_t)) {
        log_error("recvmsg() returned not enough data: %d", n);
        return NC_ERROR;
    }

	if (nc_process_role == NC_PROCESS_WORKER) {
	    if (message->command == NC_CMD_OPEN_CHANNEL) {
			log_error("recvmsg() channel command: %d from %d", NC_CMD_OPEN_CHANNEL, nc_worker_channel);
	    
			//
			// messagnc_channel_msg_te;
			// send to reload via socketpair to master process
			//memset(&message, 0, sizeof(nc_channel_msg_t));
			//message.command = NC_CMD_OPEN_CHANNEL;
			//message.slot = nc_process_slot;
			//nc_write_channel(nc_worker_channel, &message, sizeof(nc_channel_msg_t));		

		}
		if (message->command == NC_CMD_TERMINATE) {
			log_error("recvmsg() channel command: %d from %d", NC_CMD_TERMINATE, nc_worker_channel);
			exit(1);
	    }
		if (message->command == NC_CMD_RELOAD_DONE) {
			log_error("recvmsg() channel command: %d from %d", NC_CMD_RELOAD_DONE, nc_worker_channel);
			exit(1);
	    }
		
		if (message->command == NC_CMD_GET_STATS) {
			nc_get_stats_cmd = 1;
		}
		
	} else if (nc_process_role == NC_PROCESS_MASTER) {
#ifdef GRACEFUL
		if (message->command == NC_CMD_RELOAD) {
			slot = message->slot;
		
			//nc_processes[slot] is old process which will go to die in the future.
			nc_processes[slot].isNew = 0;

			log_error("recvmsg() channel command: %d from %d, worker index %d", NC_CMD_RELOAD, s,
																	nc_processes[slot].idxWorker);

			nc_start_new_worker(&nc_processes[slot]);

			if (nc_cnt_reload == NC_CNT_RELOAD_MAGIC) {
				nc_cnt_reload = 1;
				log_error("tyson, no++, nc_reload_start: %d, nc_cnt_reload: %d", nc_reload_start, nc_cnt_reload);
			} else {
				nc_cnt_reload++;
				log_error("tyson, ++ nc_reload_start: %d, nc_cnt_reload: %d", nc_reload_start, nc_cnt_reload);
			}
		}
		if (message->command == NC_CMD_RELOAD_DONE) {
			slot = message->slot;

			nc_channel_msg_t reply;
			memset(&reply, 0, sizeof(nc_channel_msg_t));
   			reply.command = NC_CMD_RELOAD_DONE;
			nc_write_channel(nc_processes[slot].channel[0], &reply, sizeof(nc_channel_msg_t));
			
			
			close(nc_processes[slot].channel[0]);
			log_error("recvmsg() channel command: %d from %d, worker index %d", NC_CMD_RELOAD_DONE, s,
																	nc_processes[slot].idxWorker);
			nc_cnt_reload--;
			log_error("tyson, -- nc_reload_start: %d, nc_cnt_reload: %d", nc_reload_start, nc_cnt_reload);
		}	
#endif
	}
	/*
	if (message->command == NC_CMD_REOPEN) {
		log_error("recvmsg() channel command: %d from %d", NC_CMD_REOPEN, nc_worker_channel);
		
		replyReopenMsg();
	}
	*/

    return n;
}


void
nc_pass_open_channel(nc_channel_msg_t *message)
{
	int s = message->fd;
    log_debug("pass channel:%d pid:%P fd:%d from fd: %d",
                  message->slot, message->pid, message->fd, s);

    /* TODO: NGX_AGAIN */
    nc_write_channel(s, message, sizeof(nc_channel_msg_t));
}

// handle sighup to reload children
void
nc_reap_children()
{
    int i;
	nc_channel_msg_t     message;
	int ret;
	
    //memset(&message, 0, sizeof(nc_channel_msg_t));
    //message.command = NC_CMD_TERMINATE;
	
    for (i = 0; i < nc_last_process; i++) {

        if (nc_processes[i].pid == -1
            || nc_processes[i].channel[0] == -1)
        {
            continue;
        }

        log_debug("reap children: %d pid:%P fd:%d",
                      i, nc_processes[i].pid,
                      nc_processes[i].channel[1]);
		memset(&message, 0, sizeof(nc_channel_msg_t));
    	//message.command = NC_CMD_REOPEN;
		message.command = NC_CMD_TERMINATE;
        ret = nc_write_channel(nc_processes[i].channel[0],
                          &message, sizeof(nc_channel_msg_t));
		if (kill(nc_processes[i].pid, SIGKILL) == -1) {
			log_error("term chidren pid %p fail: %s", nc_processes[i].pid, strerror(errno));
        }
		
    }
}


void
nc_term_children()
{
    int i;
	nc_channel_msg_t     message;
	int ret;
	
    //memset(&message, 0, sizeof(nc_channel_msg_t));
    //message.command = NC_CMD_TERMINATE;
	
    for (i = 0; i < nc_last_process; i++) {

        if (nc_processes[i].pid == -1
            || nc_processes[i].channel[0] == -1)
        {
            continue;
        }

        log_debug("term children: %d pid:%P fd:%d",
                      i, nc_processes[i].pid,
                      nc_processes[i].channel[1]);
		memset(&message, 0, sizeof(nc_channel_msg_t));
    	message.command = NC_CMD_TERMINATE;
		
        ret = nc_write_channel(nc_processes[i].channel[0],
                          &message, sizeof(nc_channel_msg_t));

		if (kill(nc_processes[i].pid, SIGKILL) == -1) {
			log_error("term chidren pid %p fail: %s", nc_processes[i].pid, strerror(errno));
        }
    }
}



void
nc_signal_worker_processes(int signo)
{
    int      i;
    int      err;
    nc_channel_msg_t  message;

    memset(&message, 0, sizeof(nc_channel_msg_t));
    switch (signo) {
    case SIGQUIT:
        message.command = NC_CMD_QUIT;
        break;
    case SIGTERM:
        message.command = NC_CMD_TERMINATE;
        break;

    default:
        message.command = 0;
    }

    message.fd = -1;
	
	//broadcast
    for (i = 0; i < nc_last_process; i++) {


        if (nc_processes[i].pid == -1) {
            continue;
        }

        if (nc_processes[i].exiting
            && signo == SIGQUIT)
        {
            continue;
        }

        if (message.command) {
            if (nc_write_channel(nc_processes[i].channel[0],
                                  &message, sizeof(nc_channel_msg_t))
                == NC_OK)
            {	/*
                if (signo != SIGINFO) {
                    nc_processes[i].exiting = 1;
                }*/

                continue;
            }
        }

        if (kill(nc_processes[i].pid, signo) == -1) {
            err = errno;
            log_error("kill(%P, %d) failed, %s", nc_processes[i].pid, signo, strerror(err));

            if (err == ESRCH) {
                nc_processes[i].exited = 1;
                nc_processes[i].exiting = 0;
                nc_reap = 1;
            }

            continue;
        }
		/*
        if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
            nc_processes[i].exiting = 1;
        }*/
    }
}








void
nc_close_channel(int *fd)
{
    if (close(fd[0]) == -1) {
        log_error( "close() channel failed %s", strerror(errno));
    }
	
    if (close(fd[1]) == -1) {
        log_error("close() channel failed %s", strerror(errno));
    }
}

