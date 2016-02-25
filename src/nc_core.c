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
#include <unistd.h>
#include <nc_core.h>
#include <nc_conf.h>
#include <nc_server.h>
#include <nc_proxy.h>

static uint32_t ctx_id; /* context generation */

static rstatus_t
core_calc_connections(struct context *ctx)
{
    int status;
    struct rlimit limit;

    status = getrlimit(RLIMIT_NOFILE, &limit);
    if (status < 0) {
        log_error("getrlimit failed: %s", strerror(errno));
        return NC_ERROR;
    }

    ctx->max_nfd = (uint32_t)limit.rlim_cur;
    ctx->max_ncconn = ctx->max_nfd - ctx->max_nsconn - RESERVED_FDS;
    log_debug(LOG_NOTICE, "max fds %"PRIu32" max client conns %"PRIu32" "
              "max server conns %"PRIu32"", ctx->max_nfd, ctx->max_ncconn,
              ctx->max_nsconn);

    return NC_OK;
}

static void
core_close(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    char type, *addrstr;

    ASSERT(conn->sd > 0);

    if (conn->client) {
        type = 'c';
        addrstr = nc_unresolve_peer_desc(conn->sd);
    } else {
        type = conn->proxy ? 'p' : 's';
        addrstr = nc_unresolve_addr(conn->addr, conn->addrlen);
    }
	
    log_debug(LOG_NOTICE, "close %c %d '%s' on event %04"PRIX32" eof %d done "
              "%d rb %zu sb %zu%c %s", type, conn->sd, addrstr, conn->events,
              conn->eof, conn->done, conn->recv_bytes, conn->send_bytes,
              conn->err ? ':' : ' ', conn->err ? strerror(conn->err) : "");

    status = event_del_conn(ctx->evb, conn);
    if (status < 0) {
        log_warn("event del conn %c %d failed, ignored: %s",
                 type, conn->sd, strerror(errno));
    }

    conn->close(ctx, conn);
}

static int compare_pool_conf(struct conf_pool *cp_old, struct conf_pool *cp_new) {
	
	if (string_compare(&cp_new->name, &cp_old->name) != 0) {
		return false;
	}
	
	if (cp_old->redis != cp_new->redis) {
		return false;
	}
	
	if(string_compare(&cp_old->redis_auth, &cp_new->redis_auth) != 0) {
		return false;	
	}

	if(string_compare(&cp_old->listen.pname, &cp_new->listen.pname) != 0) {
		return false;	
	}
	return true;
}


static int compare_server_conf(struct conf_server *cs_old, struct conf_server *cs_new) {
	
	if (string_compare(&cs_new->pname, &cs_old->pname) != 0) {
		return false;
	}
	
	if (string_compare(&cs_new->name, &cs_old->name) != 0) {
		return false;
	}

	return true;
}


static void check_pool_update(struct conf_pool *cp_old, struct conf_pool *cp_new)
{	
    uint32_t i, nelem, j, melem;
	struct conf_server* cs_old  = NULL;
	struct conf_server* cs_new	= NULL;

	struct array* servers_old = &cp_old->server;
	struct array* servers_new = &cp_new->server; 

	int found = 0;
	

	// check servers
	// check via old  // delete, update
	for (i = 0, nelem = array_n(servers_old); i < nelem; i++) {
		cs_old = array_get(servers_old, i);
		found = 0;
		//log_error("tyson %.*s", cs_old->pname.len, cs_old->pname.data);  //127.0.0.1:6379:1
		//log_error("tyson %.*s", cs_old->name.len, cs_old->name.data);	 // myseerver
		//log_error("tyson %.*s", cs_old->addrstr.len, cs_old->addrstr.data);  // 127.0.0.1

		for (j = 0, melem = array_n(servers_new); j < melem; j++) {
			cs_new = array_get(servers_new, j); 
			if (compare_server_conf(cs_old, cs_new)) {
				found = 1;
				break;
			}
		}
		if (!found) {
			log_error("server via old not found %d delete", i);
			cs_old->change = CONF_CHANGE_DEL;
		}	
	}
	
	// check via new  // add
	for (i = 0, nelem = array_n(servers_new); i < nelem; i++) {
		cs_new = array_get(servers_new, i);
		found = 0;
		
		for (j = 0, melem = array_n(servers_old); j < melem; j++) {
			cs_old = array_get(servers_old, j); 
			if (compare_server_conf(cs_old, cs_new)) {
				found = 1;
				break;
			}
		}
		if (!found) {
			log_error("server via new not found %d add", i);
			cs_new->change = CONF_CHANGE_ADD;
		}	
	}
	
}

static int check_conf_update(struct context *ctx_old, struct context *ctx_new)
{
	struct array* pool_old 	= &ctx_old->cf->pool;
	struct array* pool_new 	= &ctx_new->cf->pool;
	uint32_t i, nelem, j, melem;

	struct conf_pool *cp_old 	= NULL;
	struct conf_pool *cp_new 	= NULL;
	
	int found = 0;

	if (array_n(pool_old) != array_n(pool_new)) {
		return false;
	}
	
	// check server pool
	// check via old  // delete, update
	for (i = 0, nelem = array_n(pool_old); i < nelem; i++) {
		cp_old = array_get(pool_old, i);
		found = 0;
		for (j = 0, melem = array_n(pool_new); j < melem; j++) {
			cp_new = array_get(pool_new, j); 
			if (compare_pool_conf(cp_old, cp_new)) {
				found = 1;
				break;
			}
		}
		if (!found) {
			cp_old->change = CONF_CHANGE_DEL;
			log_error("pool via old not found %d", i);
			return false;
		}	

		// check server
		if (found) {
			log_error("pool via old found %d", i);
			check_pool_update(cp_old, cp_new);		
		}
	}

	// check via new   // add
	for (i = 0, nelem = array_n(pool_new); i < nelem; i++) {
		cp_new = array_get(pool_new, i);
		found = 0;
		for (j = 0, melem = array_n(pool_old); j < melem; j++) {
			cp_old = array_get(pool_old, j); 
			if (compare_pool_conf(cp_old, cp_new)) {
				found = 1;
				break;
			}
		}
		if (!found) {
			cp_new->change = CONF_CHANGE_ADD;
			return false;
		}
		if (found) {
			// log_error("pool via new found %d", i);
			// don't support adding pool dynamically
		}	
	}

	return true;
}



rstatus_t
delete_old_server(void *elem, void *data)
{
	rstatus_t status;

	struct server *s = elem;
	struct conf_server* cs = data;
	struct conn *conn = NULL;
	int i = 0;

	log_error("tyson here %d", i);

	if (string_compare(&s->pname, &cs->pname) == 0 && 
	   string_compare(&s->name, &cs->name) == 0) {

	   log_error("tyson %.*s", s->name.len, s->name.data); 
	   ASSERT(s != NULL);

	   while (!TAILQ_EMPTY(&s->s_conn_q)) {
		  ASSERT(s->ns_conn_q > 0);
		  conn = TAILQ_FIRST(&s->s_conn_q);
		  core_close(s->owner->ctx, conn);
		  //conn->close(sp->ctx, conn);
		}
		ASSERT(TAILQ_EMPTY(&s->s_conn_q) && s->ns_conn_q == 0);
	}
    	
    return NC_OK;


}




static rstatus_t server_pool_update1(struct conf_server* cs, struct instance *nci, 
									  struct string* pool_name) 
{
	struct array* pool = &nci->ctx->pool;
	struct server_pool *sp = NULL; 

	struct array* server = NULL;
	struct array* server_tmp = NULL;

	struct server *s = NULL;
	struct server *s_tmp = NULL;
	struct conn *conn = NULL;

	rstatus_t status;

	uint32_t i, nelem;
	int found = 0;
	int found_server = 0;
	int nserver = 0;
	
	for (i = 0, nelem = array_n(pool); i < nelem; i++) {
		sp= array_get(pool, i);
		if (string_compare(&sp->name, pool_name) == 0) {
			found = 1;
			break;
		}	
	}
	if (found) {
		if (cs->change == CONF_CHANGE_ADD) {

			ASSERT(sp!=NULL);
			server = &sp->server;
			ASSERT(array_n(server)!=0);
			s = array_push(server);
			ASSERT(s != NULL);

			s->idx = array_idx(server, s);
			s->owner = NULL;
			s->pname = cs->pname;
			s->name = cs->name;
			s->addrstr = cs->addrstr;
			s->port = (uint16_t)cs->port;
			s->weight = (uint32_t)cs->weight;
		    nc_memcpy(&s->info, &cs->info, sizeof(cs->info));
		    s->ns_conn_q = 0;
		    TAILQ_INIT(&s->s_conn_q);
		    s->next_retry = 0LL;
		    s->failure_count = 0;
			// 
			s->owner = sp;
			nci->ctx->max_nsconn += sp->server_connections;
			
			// preconnect 
			if (sp->preconnect) {
			    conn = server_conn(s);
				if (conn == NULL) {
		        	return NC_ENOMEM;
		    	}
				
				status = server_connect(sp->ctx, s, conn);
				if (status != NC_OK) {
					log_error("connect to server '%.*s' failed, ignored: %s",
						s->pname.len, s->pname.data, strerror(errno));
					server_close(sp->ctx, conn);
				}
			}

			// ketama
			server_pool_run(sp);
		    log_debug(LOG_VERB, "update, add new server %"PRIu32" '%.*s'",
		              s->idx, s->pname.len, s->pname.data);
			log_error("add new server %"PRIu32" '%.*s'",
		              s->idx, s->pname.len, s->pname.data);
	
		}else if (cs->change == CONF_CHANGE_DEL){
			ASSERT(sp!=NULL);
			server = &sp->server;
			ASSERT(array_n(server)!=0);
			status = array_each(server, delete_old_server, cs);

			nserver = array_n(server) - 1;
			ASSERT(nserver != 0);
			
			// init the server_tmp array
			server_tmp = nc_alloc(sizeof(struct array));
			array_null(server_tmp);
			array_init(server_tmp, nserver, sizeof(struct server));
			if (status != NC_OK) {
				return status;
			}
			
			//status = array_each(conf_pool, conf_pool_master, server_pool);

			// pop the server array, push the other server into the server_tmp
			while (array_n(server) != 0) {
				s = array_pop(server);
				if (string_compare(&s->pname, &cs->pname) == 0 && 
				   string_compare(&s->name, &cs->name) == 0) {
					
				    log_error("tyson %.*s", s->name.len, s->name.data); 
					found_server = 1;

					/*
					ASSERT(s != NULL);

					while (!TAILQ_EMPTY(&s->s_conn_q)) {
				        ASSERT(s->ns_conn_q > 0);
				        conn = TAILQ_FIRST(&s->s_conn_q);
						core_close(sp->ctx, conn);
				        //conn->close(sp->ctx, conn);
				    }
					ASSERT(TAILQ_EMPTY(&s->s_conn_q) && s->ns_conn_q == 0);
					*/
				} else {
					s_tmp = array_push(server_tmp);
					nc_memcpy(s_tmp, s, sizeof(struct server));
					s_tmp->idx = array_idx(server_tmp, s_tmp);
					TAILQ_INIT(&s_tmp->s_conn_q);

				}
			}
			
			
			if (found_server) {
				log_error("delete server fould server while reconfiguration %d", found_server);
			} else {
				log_error("delete server fail while reconfiguration %d", found_server);
			}
			ASSERT(array_n(server_tmp) == nserver);
			sp->server = *server_tmp;
			
			

			// ketama
			server_pool_run(sp);
		    log_debug(LOG_VERB, "update, delete old server %"PRIu32" '%.*s'",
		              s->idx, s->pname.len, s->pname.data);
			log_error("delete old server %"PRIu32" '%.*s'",
		              s->idx, s->pname.len, s->pname.data);
		}
		
	    return NC_OK;

	}else {
		log_error("server_pool_update failure: can't find dedicate pool %d", found);
		return NC_ERROR;
	}	
	
}


// only check server change in this version, pool change is not supported in this version.
static rstatus_t update_pool_server(struct context *ctx, struct instance *nci) {
	uint32_t i, nelem, j, melem;
	rstatus_t status = NC_OK;

	struct array* pool = &ctx->cf->pool;
	struct array* servers = NULL;

	struct conf_pool *cp = NULL;
	struct conf_server *cs = NULL;
	
	
	// update pool server online	
	for (i = 0, nelem = array_n(pool); i < nelem; i++) {
		cp = array_get(pool, i);
		servers = &cp->server;
		for (j = 0, melem = array_n(servers); j < melem; j++) {
			cs = array_get(servers, j);
			if (cs->change == CONF_CHANGE_ADD) {
				log_error("add new server according to configuration change %d", i);
				status = server_pool_update1(cs, nci, &cp->name);
				if(status != NC_OK) {
					return status;
					//exit(1);
				}
				stats_destroy(nci->ctx->stats);
				nci->ctx->stats = stats_create(nci->stats_port+nc_worker_index, nci->stats_addr, nci->stats_interval,
                              nci->hostname, &nci->ctx->pool);	
				
			} else if (cs->change == CONF_CHANGE_DEL) {
				log_error("delete old server according to configuration change %d", i);
				status = server_pool_update1(cs, nci, &cp->name); 
				if (status != NC_OK) {
					return status;
					//exit(1);
				}
				stats_destroy(nci->ctx->stats);
				nci->ctx->stats = stats_create(nci->stats_port+nc_worker_index, nci->stats_addr, nci->stats_interval,
                              nci->hostname, &nci->ctx->pool);	
	
			}
		}
	
	}
	return status;
}

void
core_ctx_get_stats(struct instance *nci)
{	
	/*
	uint32_t i, nelem, j, melem;
	struct array* pool = NULL;
	struct array* servers = NULL;
	struct conf_pool *cp = NULL;
	struct conf_server *cs = NULL;

	pool = &nci->ctx->cf->pool;
	for (i = 0, nelem = array_n(pool); i < nelem; i++) {
		cp = array_get(pool, i);
		servers = &cp->server;
		for (j = 0, melem = array_n(servers); j < melem; j++) {
			cs = array_get(servers, j);
			log_error("tyson pool: %.*s server lenght, %d", cp->name.len, cp->name.data, array_n(servers)); 	
		}
	}
	*/
	
	int i;
	nc_channel_msg_t message;
	memset(&message, 0, sizeof(nc_channel_msg_t));
	message.command = NC_CMD_GET_STATS;

	//broadcast
    for (i = 0; i < nc_last_process; i++) 
	{
        if (nc_processes[i].pid == -1 || nc_processes[i].pid == 0) 
		{
            continue;
        }
        if (message.command)
		{
            if (nc_write_channel(nc_processes[i].channel[0],
                                  &message, sizeof(nc_channel_msg_t))
                == NC_OK)
            {	
                continue;
            }
        }

    }
	
}


void
core_ctx_recreate(struct instance *nci)
{	
	struct context *ctx;
	rstatus_t status;
	
	uint32_t i, nelem, j, melem;
	struct array* pool = NULL;
	struct array* servers = NULL;
	struct conf_pool *cp = NULL;
	struct conf_server *cs = NULL;


    ctx = nc_alloc(sizeof(*ctx));
    if (ctx == NULL) {
        return;
    }
 	
    ctx->cf = conf_create(nci->conf_filename);
    if (ctx->cf == NULL) {
		log_stderr("nutcracker: configuration file '%s' syntax is invalid",
                   nci->conf_filename);
        nc_free(ctx);
        return;
    }

    if (check_conf_update(nci->ctx ,ctx)) {
		// fisrt new, then old => add firstly, then delete
		status = update_pool_server(ctx, nci);		// new
		if (status != NC_OK) {
			return;
		}

		status = update_pool_server(nci->ctx, nci);	// old
		if (status != NC_OK) {
			return;
		}
		
	} else {
		log_error("bilitw: currently DO NOT support pool dynamic update! %s", nci->conf_filename);
		return;
	}

	// clear change flag
	// bind ctx to nci
	if (status == NC_OK ) {
		nci->ctx->cf = ctx->cf;
		pool = &ctx->cf->pool;
		for (i = 0, nelem = array_n(pool); i < nelem; i++) {
			cp = array_get(pool, i);
			cp->change = 0;
			servers = &cp->server;
			for (j = 0, melem = array_n(servers); j < melem; j++) {
				cs = array_get(servers, j);	
				cs->change = 0;
			}
		}
		
	}

}








static struct context *
core_ctx_create(struct instance *nci)
{
    rstatus_t status;
    struct context *ctx;

    ctx = nc_alloc(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->id = ++ctx_id;
    ctx->cf = NULL;
    ctx->stats = NULL;
    ctx->evb = NULL;
    array_null(&ctx->pool);
    // ctx->max_timeout = nci->stats_interval;
	ctx->max_timeout = 1000;   /* 1000 msec*/

    ctx->timeout = ctx->max_timeout;
    ctx->max_nfd = 0;
    ctx->max_ncconn = 0;
    ctx->max_nsconn = 0;

    /* parse and create configuration */
    ctx->cf = conf_create(nci->conf_filename);
    if (ctx->cf == NULL) {
        nc_free(ctx);
        return NULL;
    }

    /* initialize server pool from configuration */
    status = server_pool_init(&ctx->pool, &ctx->cf->pool, ctx);
    if (status != NC_OK) {
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    /*
     * Get rlimit and calculate max client connections after we have
     * calculated max server connections
     */
    status = core_calc_connections(ctx);
    if (status != NC_OK) {
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }
	
    /* create stats per server pool */
    //ctx->stats = stats_create(nci->stats_port+nc_worker_index, nci->stats_addr, nci->stats_interval,
	ctx->stats = stats_create(nci->stats_port, nci->stats_addr, nci->stats_interval,
                              nci->hostname, &ctx->pool);
    if (ctx->stats == NULL) {
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }
    

    /* initialize event handling for client, proxy and server */
    ctx->evb = event_base_create(EVENT_SIZE, &core_core);
    if (ctx->evb == NULL) {
        stats_destroy(ctx->stats);
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    /* epoll add the controll channel */
    status = event_add_channel(ctx->evb, &env_global.ctrl_msg);
    if (status < 0){
	 event_del_channel(ctx->evb, &env_global.ctrl_msg);
   	 event_base_destroy(ctx->evb);
   	 stats_destroy(ctx->stats);
	 server_pool_deinit(&ctx->pool);
	 conf_destroy(ctx->cf);
	 nc_free(ctx);
   	return NULL;
    }

    /* preconnect? servers in server pool */
    status = server_pool_preconnect(ctx);
    if (status != NC_OK) {
	  event_del_channel(ctx->evb, &env_global.ctrl_msg);
	  server_pool_disconnect(ctx);
	  event_base_destroy(ctx->evb);
        stats_destroy(ctx->stats);
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    /* initialize proxy per server pool */
    status = proxy_init(ctx);
    if (status != NC_OK) {
		event_del_channel(ctx->evb, &env_global.ctrl_msg);
        server_pool_disconnect(ctx);
        event_base_destroy(ctx->evb);
        stats_destroy(ctx->stats);
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    log_debug(LOG_VVERB, "created ctx %p id %"PRIu32"", ctx, ctx->id);

    return ctx;
}

static void
core_ctx_destroy(struct context *ctx)
{
    log_debug(LOG_VVERB, "destroy ctx %p id %"PRIu32"", ctx, ctx->id);
    proxy_deinit(ctx);
    server_pool_disconnect(ctx);
    event_base_destroy(ctx->evb);
    stats_destroy(ctx->stats);
    server_pool_deinit(&ctx->pool);
    conf_destroy(ctx->cf);
    nc_free(ctx);
}

struct context *
core_start(struct instance *nci)
{
    struct context *ctx;

    mbuf_init(nci);
    msg_init();
    conn_init();

    ctx = core_ctx_create(nci);
    if (ctx != NULL) {
        nci->ctx = ctx;
        return ctx;
    }

    conn_deinit();
    msg_deinit();
    mbuf_deinit();

    return NULL;
}

void
core_stop(struct context *ctx)
{
    conn_deinit();
    msg_deinit();
    mbuf_deinit();
    core_ctx_destroy(ctx);
}

static rstatus_t
core_recv(struct context *ctx, struct conn *conn)
{
    rstatus_t status;

    status = conn->recv(ctx, conn);
    if (status != NC_OK) {
        log_debug(LOG_INFO, "recv on %c %d failed: %s",
                  conn->client ? 'c' : (conn->proxy ? 'p' : 's'), conn->sd,
                  strerror(errno));
    }

    return status;
}

static rstatus_t
core_send(struct context *ctx, struct conn *conn)
{
    rstatus_t status;

    status = conn->send(ctx, conn);
    if (status != NC_OK) {
        log_debug(LOG_INFO, "send on %c %d failed: status: %d errno: %d %s",
                  conn->client ? 'c' : (conn->proxy ? 'p' : 's'), conn->sd,
                  status, errno, strerror(errno));
    }

    return status;
}



static void
core_error(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    char type = conn->client ? 'c' : (conn->proxy ? 'p' : 's');

    status = nc_get_soerror(conn->sd);
    if (status < 0) {
        log_warn("get soerr on %c %d failed, ignored: %s", type, conn->sd,
                  strerror(errno));
    }
    conn->err = errno;

    core_close(ctx, conn);
}

static void
core_timeout(struct context *ctx)
{
#ifdef GRACEFUL
	nc_channel_msg_t message;
	if (nc_reload) {

		uint64_t _reload_delta = nc_msec_now() - env_global.reload_time;

		if (_reload_delta > env_global.reload_timeout || !conn_ncurr_cconn()) {
			log_error("worker %d(old) quit!!!", nc_worker_index);
			
			// send to reload_done via socketpair to master process
			memset(&message, 0, sizeof(nc_channel_msg_t));
			message.command = NC_CMD_RELOAD_DONE;
			message.slot = nc_process_slot;
			nc_write_channel(nc_worker_channel, &message, sizeof(nc_channel_msg_t));
			
			if (nc_set_blocking(nc_worker_channel) < 0) {
	        	log_error("set channel %d block failed while core timeout %s", 
	            nc_worker_channel , strerror(errno));
		    }
			nc_read_channel(nc_worker_channel, &env_global.ctrl_msg, sizeof(nc_channel_msg_t));
			
			//nc_reload = 0;
			return;
		}
	}

#endif

    for (;;) {
        struct msg *msg;
        struct conn *conn;
        int64_t now, then;

        msg = msg_tmo_min();
        if (msg == NULL) {
            ctx->timeout = ctx->max_timeout;
            return;
        }

        /* skip over req that are in-error or done */

        if (msg->error || msg->done) {
            msg_tmo_delete(msg);
            continue;
        }

        /*
         * timeout expired req and all the outstanding req on the timing
         * out server
         */

        conn = msg->tmo_rbe.data;
        then = msg->tmo_rbe.key;

        now = nc_msec_now();
        if (now < then) {
            int delta = (int)(then - now);
            ctx->timeout = MIN(delta, ctx->max_timeout);
            return;
        }

		int timeout = server_timeout(conn);
   		if (timeout <= 0) {
			log_debug(LOG_ERR, "req %"PRIu64" on s %d timedout", msg->id, conn->sd);
	        msg_tmo_delete(msg);
		} else {
	        log_debug(LOG_INFO, "req %"PRIu64" on s %d timedout", msg->id, conn->sd);
	        msg_tmo_delete(msg);
	        conn->err = ETIMEDOUT;
	        core_close(ctx, conn);
		}
    }
}

rstatus_t
core_core(void *arg, uint32_t events)
{
    rstatus_t status;
    struct conn *conn = arg;
    struct context *ctx;

    if (conn->owner == NULL) {
        log_warn("conn is already unrefed!");
        return NC_OK;
    }

    ctx = conn_to_ctx(conn);

    log_debug(LOG_VVERB, "event %04"PRIX32" on %c %d", events,
              conn->client ? 'c' : (conn->proxy ? 'p' : 's'), conn->sd);

    conn->events = events;

    /* error takes precedence over read | write */
    if (events & EVENT_ERR) {
        core_error(ctx, conn);
        return NC_ERROR;
    }

    /* read takes precedence over write */
    if (events & EVENT_READ) {
        status = core_recv(ctx, conn);
        if (status != NC_OK || conn->done || conn->err) {
            core_close(ctx, conn);
            return NC_ERROR;
        }
    }

    if (events & EVENT_WRITE) {
        status = core_send(ctx, conn);
        if (status != NC_OK || conn->done || conn->err) {
            core_close(ctx, conn);
            return NC_ERROR;
        }
    }

    return NC_OK;
}

rstatus_t
core_loop(struct context *ctx)
{
    int nsd;

    nsd = event_wait(ctx->evb, ctx->timeout);
    if (nsd < 0) {
        return nsd;
    }

    core_timeout(ctx);

    stats_swap(ctx->stats);

    return NC_OK;
}



#ifdef GRACEFUL
void
core_reload(struct instance *nci) 
{	
	char tmp_name[100];
	struct conn** pc;
	struct conn*  c;
	nc_channel_msg_t message;

	while(array_n(&nci->ctx->listen_conns)) {
		pc = array_pop(&nci->ctx->listen_conns);
		c = *pc;
		core_close(nci->ctx, c);
	}
	// change name	
	sprintf(tmp_name, "worker %d(old)", nc_worker_index);
	nc_setproctitle(tmp_name);
	
	// set reload flag
	nc_reload = 1;
	env_global.reload_time = nc_msec_now();

	// send to reload via socketpair to master process
	memset(&message, 0, sizeof(nc_channel_msg_t));
	message.command = NC_CMD_RELOAD;
	message.slot = nc_process_slot;
	nc_write_channel(nc_worker_channel, &message, sizeof(nc_channel_msg_t));
	
	// close socketpair		
	// close stats	

	return;
}
#endif
