
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NC_PROCESS_H_INCLUDED_
#define _NC_PROCESS_H_INCLUDED_



// process role
#define NC_PROCESS_MASTER     1
#define NC_PROCESS_WORKER     2


// channel control message
#define NC_CMD_OPEN_CHANNEL     1
#define NC_CMD_CLOSE_CHANNEL    2
#define NC_CMD_QUIT           3
#define NC_CMD_TERMINATE      4
#define NC_CMD_RELOAD         5
#define NC_CMD_RELOAD_DONE	6
#define NC_CMD_REOPEN_REPLY   7
#define NC_CMD_GET_STATS	  8

#define NC_CNT_RELOAD_MAGIC   -10		


#define NC_PROCESS_STATE_RUNNING		0
#define NC_PROCESS_STATE_RELOADING		1


typedef pid_t       nc_pid_t;

#define NC_INVALID_PID  -1

typedef void (*nc_spawn_proc_pt) (void *data);

typedef struct {
    nc_pid_t           pid;
	
	
	int					idxWorker;

	int                 status;
    int        			channel[2];
	int 				channel_back[2];

    nc_spawn_proc_pt   proc;
    void               *data;
    char               *name;

    unsigned            respawn:1;
    unsigned            just_spawn:1;
    unsigned            detached:1;
    unsigned            exiting:1;
    unsigned            exited:1;
	unsigned 			isNew:1;
} nc_process_t;




#define NC_MAX_PROCESSES         512
#define NC_PROCESS_MAGIC_JUMP    256
#define NC_PROCESS_NORESPAWN     -1
#define NC_PROCESS_JUST_SPAWN    -2
#define NC_PROCESS_RESPAWN       -3
#define NC_PROCESS_JUST_RESPAWN  -4
#define NC_PROCESS_DETACHED      -5

#define nc_getpid   getpid

#ifndef nc_log_pid
#define nc_log_pid  nc_pid
#endif


nc_pid_t nc_spawn_process( nc_spawn_proc_pt proc, int data,
    char *name, int respawn);


rstatus_t tw_master_listen(int family, struct sockaddr* addr, socklen_t addrlen, int backlog);
void tw_worker_cycle(void *data);
void nc_process_get_status(void);

extern nc_pid_t      nc_pid;
extern int    		 nc_channel;	
extern int           nc_process_slot;
extern int           nc_worker_channel;
extern int           nc_worker_channel_write;


extern int           nc_last_process;
extern nc_process_t  nc_processes[NC_MAX_PROCESSES];
extern int			 nc_process_role;
extern int 			 nc_worker_index;

extern struct env_master env_global;
extern struct instance   nci_global;

extern int  nc_reap;
extern int  nc_sigio;
extern int  nc_sigalarm;
extern int  nc_terminate;
extern int	nc_quit;
//
extern int	nc_reload;
extern int	nc_reload_start;
extern int	nc_cnt_reload;
extern int 	nc_get_stats_cmd;


extern int 	nc_debug_quit;
extern int  nc_exiting;
extern int  nc_reopen;
extern int  nc_daemonized;

extern int  nc_noaccept;
extern int  nc_noaccepting;
extern int  nc_restart;


#endif /* _NGX_PROCESS_H_INCLUDED_ */

