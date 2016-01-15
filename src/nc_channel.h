
#ifndef _NC_CHANNEL_H_INCLUDED_
#define _NC_CHANNEL_H_INCLUDED_


#define CHANNEL_BUFFER_MAX_LENGTH     1024

typedef pid_t       nc_pid_t;
typedef struct {
     int  command;
     nc_pid_t   pid;
     int   slot;
     int   fd;
} nc_channel_msg_t;

/*
typedef struct {
  int command;
  nc_pid_t pid;
} nc_channel_msg_t;*/

int nc_write_channel(int s, nc_channel_msg_t *message, size_t size);
int nc_read_channel(int s, nc_channel_msg_t *message, size_t size);
void nc_close_channel(int *fd);
void nc_signal_worker_processes(int signo);


#endif /* _NC_CHANNEL_H_INCLUDED_ */


