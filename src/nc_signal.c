/*
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

#include <stdlib.h>
#include <signal.h>

#include <nc_core.h>



static struct signal signals[] = {
    // none defined, extend in the future
    { SIGUSR1,  "SIGUSR1", 0,                 signal_handler },
    { SIGUSR2,  "SIGUSR2", 0,                 signal_handler },
    
    // log related
    { SIGTTIN,  "SIGTTIN", 0,                 signal_handler },
    { SIGTTOU,  "SIGTTOU", 0,                 signal_handler },
    { SIGHUP,   "SIGHUP",  0,                 signal_handler },

    // zombie process
    { SIGCHLD,  "SIGCHLD", 0,                 signal_handler  },
    
    // fast quit
    { SIGINT,   "SIGINT",  0,                 signal_handler },
    { SIGTERM,  "SIGTERM",   0, 			  signal_handler},
    // graceful shutdown
    { SIGQUIT,   "SIGQUIT",   0, 			  signal_handler},
    
    // alarm
    { SIGALRM,  "SIGALRM",  0,                signal_handler },
	// graceful shutdown of worker processes
	{ SIGWINCH,  "SIGWINCH",  0,               signal_handler},
	
    // Segment fault, core dump
    { SIGSEGV,  "SIGSEGV", (int)SA_RESETHAND,  signal_handler },
    
    // rst, connection unexpected quit
    { SIGPIPE,  "SIGPIPE",  0,                 SIG_IGN },
	//{ SIGIO,	"SIGIO",  0,				  SIG_IGN },
    { 0,        NULL,     0,                 NULL }
};




rstatus_t
signal_init(void)
{
    struct signal *sig;

    for (sig = signals; sig->signo != 0; sig++) {
        rstatus_t status;
        struct sigaction sa;

        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sig->handler;
        sa.sa_flags = sig->flags;
        sigemptyset(&sa.sa_mask);

        status = sigaction(sig->signo, &sa, NULL);
        if (status < 0) {
            //log_error();
	      log_error("sigaction(%s) failed: %s", sig->signame,
                      strerror(errno));	
            return NC_ERROR;
        }
    }

    return NC_OK;
}




void
signal_deinit(void)
{
}



void
signal_handler(int signo)
{
    struct signal *sig;
    void (*action)(void);
    char *actionstr;
    bool done;

    for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }
    ASSERT(sig->signo != 0);

    actionstr = "";
    action = NULL;
    done = false;

	if (nc_process_role == NC_PROCESS_MASTER ) 
	{
		switch (signo) {
	    case SIGUSR1:
	        break;

	    case SIGUSR2:
	        break;

	    case SIGTTIN:
	        actionstr = ", up logging level";
	        action = log_level_up;
	        break;

	    case SIGTTOU:
	        actionstr = ", down logging level";
	        action = log_level_down;
	        break;

	    case SIGHUP:
	        actionstr = ", graceful reload configuration";
	        //action = log_reopen;
#ifdef GRACEFUL
			if (!nc_reload_start) {
				log_error("start reload children worker %s ", actionstr);
				nc_reload = 1;
			} else {
				log_error("deny to reload children worker due to children in reload status %s ", actionstr);
			}
#endif
	        break;


		// control signalling
		// best effort
		case SIGTERM:
	    case SIGINT:
	        done = true;
	        actionstr = ", fast exiting";
		    /*action =  restart*/
			nc_terminate = 1;
	        break;

	    case SIGQUIT:
			nc_quit = 1;
			actionstr = ", graceful shutting down";
			break;

		case SIGWINCH:
            //nc_noaccept = 1;
			//actionstr = ", stop woring processes, stop accepting connections";
			core_ctx_get_stats(&nci_global);
            break;

		case SIGCHLD:
			nc_process_get_status();
			break;

		case SIGALRM:
            nc_sigalarm = 1;
            break;
			
			
	    case SIGSEGV:
	        log_stacktrace();
	        actionstr = ", core dumping";
	        raise(SIGSEGV);
	        break;

	    default:
	        NOT_REACHED();
	    }

		if (signo!=14) {
	    	log_safe("mastere signal %d (%s) received %s", signo, sig->signame, actionstr);
		}

	    if (action != NULL) {
	        action();
	    }
		/*
	    if (done) {
	        exit(1);
	    }*/
	} 
	else if (nc_process_role == NC_PROCESS_WORKER) 
	{
		
		//log_safe("hello tyosn!");
		switch (signo) {
	    case SIGUSR1:
	        break;

	    case SIGUSR2:
	        break;

	    case SIGTTIN:
	        actionstr = ", up logging level";
	        action = log_level_up;
	        break;

	    case SIGTTOU:
	        actionstr = ", down logging level";
	        action = log_level_down;
	        break;

	    case SIGHUP:
	        actionstr = ", graceful reload configuration";
	        //action = log_reopen;
#ifdef GRACEFUL
			core_reload(&nci_global);
#else
			core_ctx_recreate(&nci_global);
#endif

	        break;


		// control signalling
		case SIGTERM:
	    case SIGINT:
	        done = true;
			log_safe("worker %d receive fast terminate signal", nc_worker_index);
			
	        actionstr = ", fast exiting";
		    //exit(1);
			//ASSERT(0);
			raise(SIGSEGV);
	        break;

		case SIGWINCH:
            //nc_debug_quit = 1;
			//core_ctx_debug(&nci_global);
	    case SIGQUIT:
			nc_quit = 1;
			actionstr = ", graceful shutting down";
			break;

	    case SIGSEGV:
	        log_stacktrace();
	        actionstr = ", core dumping";
	        raise(SIGSEGV);
	        break;

	    default:
	        NOT_REACHED();
	    }

	    //log_safe("worker signal %d (%s) received%s", signo, sig->signame, actionstr);

	    if (action != NULL) {
	        action();
	    }

	    if (done) {
	        exit(1);
	    }
	}
	else 
	{
		ASSERT(0);
	}

}




