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

#include <nc_core.h>

#ifdef NC_HAVE_EPOLL

#include <sys/epoll.h>

//#define EPOLLEXCLUSIVE (1 << 28)


struct event_base *
event_base_create(int nevent, event_cb_t cb)
{
    struct event_base *evb;
    int status, ep;
    struct epoll_event *event;

    ASSERT(nevent > 0);

    ep = epoll_create(nevent);
    if (ep < 0) {
        log_error("epoll create of size %d failed: %s", nevent, strerror(errno));
        return NULL;
    }

    event = nc_calloc(nevent, sizeof(*event));
    if (event == NULL) {
        status = close(ep);
        if (status < 0) {
            log_error("close e %d failed, ignored: %s", ep, strerror(errno));
        }
        return NULL;
    }

    evb = nc_alloc(sizeof(*evb));
    if (evb == NULL) {
        nc_free(event);
        status = close(ep);
        if (status < 0) {
            log_error("close e %d failed, ignored: %s", ep, strerror(errno));
        }
        return NULL;
    }

    evb->ep = ep;
    evb->event = event;
    evb->nevent = nevent;
    evb->cb = cb;

    log_debug(LOG_INFO, "e %d with nevent %d", evb->ep, evb->nevent);

    return evb;
}

void
event_base_destroy(struct event_base *evb)
{
    int status;

    if (evb == NULL) {
        return;
    }

    ASSERT(evb->ep > 0);

    nc_free(evb->event);

    status = close(evb->ep);
    if (status < 0) {
        log_error("close e %d failed, ignored: %s", evb->ep, strerror(errno));
    }
    evb->ep = -1;

    nc_free(evb);
}

int
event_add_in(struct event_base *evb, struct conn *c)
{
    int status;
    struct epoll_event event;
    int ep = evb->ep;

    ASSERT(ep > 0);
    ASSERT(c != NULL);
    ASSERT(c->sd > 0);

    if (c->recv_active) {
        return 0;
    }

    event.events = (uint32_t)(EPOLLIN | EPOLLET);
    event.data.ptr = c;

    status = epoll_ctl(ep, EPOLL_CTL_MOD, c->sd, &event);
    if (status < 0) {
        log_error("epoll ctl on e %d sd %d failed: %s", ep, c->sd,
                  strerror(errno));
    } else {
        c->recv_active = 1;
    }

    return status;
}

int
event_del_in(struct event_base *evb, struct conn *c)
{
    return 0;
}

int
event_add_out(struct event_base *evb, struct conn *c)
{
    int status;
    struct epoll_event event;
    int ep = evb->ep;

    ASSERT(ep > 0);
    ASSERT(c != NULL);
    ASSERT(c->sd > 0);
    ASSERT(c->recv_active);

    if (c->send_active) {
        return 0;
    }

    event.events = (uint32_t)(EPOLLIN | EPOLLOUT | EPOLLET);
    event.data.ptr = c;

    status = epoll_ctl(ep, EPOLL_CTL_MOD, c->sd, &event);
    if (status < 0) {
        log_error("epoll ctl on e %d sd %d failed: %s", ep, c->sd,
                  strerror(errno));
    } else {
        c->send_active = 1;
    }

    return status;
}

int
event_del_out(struct event_base *evb, struct conn *c)
{
    int status;
    struct epoll_event event;
    int ep = evb->ep;

    ASSERT(ep > 0);
    ASSERT(c != NULL);
    ASSERT(c->sd > 0);
    ASSERT(c->recv_active);

    if (!c->send_active) {
        return 0;
    }

    event.events = (uint32_t)(EPOLLIN | EPOLLET);
    event.data.ptr = c;

    status = epoll_ctl(ep, EPOLL_CTL_MOD, c->sd, &event);
    if (status < 0) {
        log_error("epoll ctl on e %d sd %d failed: %s", ep, c->sd,
                  strerror(errno));
    } else {
        c->send_active = 0;
    }

    return status;
}

int
event_add_channel(struct event_base *evb, nc_channel_msg_t* message)
{
    int status;
    struct epoll_event event;
    int ep = evb->ep;

    ASSERT(ep > 0);
    ASSERT(message != NULL);
    //ASSERT(message->fd > 0);

    event.events = (uint32_t)(EPOLLIN | EPOLLOUT | EPOLLET);
    event.data.ptr = message;

    status = epoll_ctl(ep, EPOLL_CTL_ADD, nc_worker_channel, &event);
    if (status < 0) {
        log_error("epoll ctl on e %d fd %d failed: %s", ep, nc_worker_channel,
                  strerror(errno));
    } 
    log_debug("epoll ctl on e %d fd %d add", ep, nc_worker_channel);
    return status;
}

int
event_del_channel(struct event_base *evb, nc_channel_msg_t* message)
{
    int status;
    int ep = evb->ep;

    ASSERT(ep > 0);
    ASSERT(message != NULL);
    //ASSERT(message->fd > 0);

    status = epoll_ctl(ep, EPOLL_CTL_DEL, nc_worker_channel, NULL);
    if (status < 0) {
        log_error("epoll ctl on e %d fd %d failed: %s", ep, nc_worker_channel,
                  strerror(errno));
    } 

    log_debug("epoll ctl on e %d fd %d delete", ep, nc_worker_channel);
    return status;
}



int
event_add_conn(struct event_base *evb, struct conn *c)
{
    int status;
    struct epoll_event event;
    int ep = evb->ep;

    ASSERT(ep > 0);
    ASSERT(c != NULL);
    ASSERT(c->sd > 0);

    event.events = (uint32_t)(EPOLLIN | EPOLLOUT | EPOLLET);
    event.data.ptr = c;

    status = epoll_ctl(ep, EPOLL_CTL_ADD, c->sd, &event);

	//ASSERT(status==0);
	
    if (status < 0) {
        log_error("epoll ctl on e %d sd %d failed: %s", ep, c->sd,
                  strerror(errno));
    } else {
        c->send_active = 1;
        c->recv_active = 1;
    }

    return status;
}

int
event_del_conn(struct event_base *evb, struct conn *c)
{
    int status;
    int ep = evb->ep;

    ASSERT(ep > 0);
    ASSERT(c != NULL);
    ASSERT(c->sd > 0);

    status = epoll_ctl(ep, EPOLL_CTL_DEL, c->sd, NULL);
    if (status < 0) {
        log_error("epoll ctl on e %d sd %d failed: %s", ep, c->sd,
                  strerror(errno));
    } else {
        c->recv_active = 0;
        c->send_active = 0;
    }

    return status;
}

int
event_wait(struct event_base *evb, int timeout)
{
    int ep = evb->ep;
    struct epoll_event *event = evb->event;
    int nevent = evb->nevent;

    ASSERT(ep > 0);
    ASSERT(event != NULL);
    ASSERT(nevent > 0);

    for (;;) {
        int i, nsd, n;

        nsd = epoll_wait(ep, event, nevent, timeout);
        if (nsd > 0) {
            for (i = 0; i < nsd; i++) {
                struct epoll_event *ev = &evb->event[i];
                uint32_t events = 0;

                log_debug(LOG_VVERB, "epoll %04"PRIX32" triggered on conn %p",
                          ev->events, ev->data.ptr);

                if (ev->events & EPOLLERR) {
                    events |= EVENT_ERR;
                }

                if (ev->events & (EPOLLIN | EPOLLHUP)) {
                    events |= EVENT_READ;
                }

                if (ev->events & EPOLLOUT) {
                    events |= EVENT_WRITE;
                }

				if(ev->data.ptr == &env_global.ctrl_msg) {
					//int sockfd=events[i].data.fd;
					nc_read_channel(nc_worker_channel, &env_global.ctrl_msg, sizeof(nc_channel_msg_t));
					 /*
					 for (;;) {
				        n = nc_read(i,&env_global.ctrl_msg, sizeof(nc_channel_msg_t));

				        log_debug(LOG_VERB, "recv on sd %d %zd of %zu", conn->sd, n, size);

				        if (n > 0) {
				            if (n < (ssize_t) size) {
				                conn->recv_ready = 0;
				            }
				            conn->recv_bytes += (size_t)n;
				            return n;
				        }

				        if (n == 0) {
				            conn->recv_ready = 0;
				            conn->eof = 1;
				            log_debug(LOG_INFO, "recv on sd %d eof rb %zu sb %zu", conn->sd,
				                      conn->recv_bytes, conn->send_bytes);
				            return n;
				        }

				        if (errno == EINTR) {
				            log_debug(LOG_VERB, "recv on sd %d not ready - eintr", conn->sd);
				            continue;
				        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				            conn->recv_ready = 0;
				            log_debug(LOG_VERB, "recv on sd %d not ready - eagain", conn->sd);
				            return NC_EAGAIN;
				        } else {
				            conn->recv_ready = 0;
				            conn->err = errno;
				            log_error("recv on sd %d failed: %s", conn->sd, strerror(errno));
				            return NC_ERROR;
				        }
				    }
					*/
				}
                else if (evb->cb != NULL) {
                    evb->cb(ev->data.ptr, events);
                } else {
                }
            }
            return nsd;
        }

        if (nsd == 0) {
            if (timeout == -1) {
               log_error("epoll wait on e %d with %d events and %d timeout "
                         "returned no events", ep, nevent, timeout);
                return -1;
            }

            return 0;
        }

        if (errno == EINTR) {
            continue;
        }

        log_error("epoll wait on e %d with %d events failed: %s", ep, nevent,
                  strerror(errno));
        return -1;
    }

    NOT_REACHED();
}

void
event_loop_stats(event_stats_cb_t cb, void *arg)
{
    int *psd = (int*)(arg);
    int status, ep;
    struct epoll_event ev;
	int sd = *psd;

    ep = epoll_create(1);
    if (ep < 0) {
        log_error("epoll create failed: %s", strerror(errno));
        return;
    }

    ev.data.fd = sd;
    ev.events = EPOLLIN;

    status = epoll_ctl(ep, EPOLL_CTL_ADD, sd, &ev);
    if (status < 0) {
        log_error("epoll ctl on e %d sd %d failed: %s", ep, sd,
                  strerror(errno));
        goto error;
    }
 	
    for (;;) {
        int n;

        n = epoll_wait(ep, &ev, 1, STATS_INTERVAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_error("epoll wait on e %d with m %d failed: %s", ep,
                      sd, strerror(errno));
            break;
        }

        cb(psd, &n);
    }

error:
    status = close(ep);
    if (status < 0) {
        log_error("close e %d failed, ignored: %s", ep, strerror(errno));
    }
    ep = -1;
}


void
event_loop_stats_ext(event_stats_cb_t cb, void *arg)
{
    struct stats *st = arg;
    for (;;) {
		usleep(10000);
		if (nc_get_stats_cmd) {
			cb(st, &nc_get_stats_cmd);
			nc_get_stats_cmd = 0;
		}
		
    }
}




#endif /* NC_HAVE_EPOLL */
