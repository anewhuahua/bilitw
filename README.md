# BILITW (bilibili twemproxy) 

**twemproxy** (pronounced "two-em-proxy"), aka **nutcracker** is a fast and lightweight proxy for [memcached](http://www.memcached.org/) and [redis](http://redis.io/) protocol. It was built primarily to reduce the number of connections to the caching servers on the backend. This, together with protocol pipelining and sharding enables you to horizontally scale your distributed caching architecture.

**bilitw** (bilibili twemproxy), which introduce multi process of twemproxy(one master and mutli worker), is order to get full use of the CPU cores. 

## Build

To build bilitw from source with _debug logs enabled_ and _assertions enabled_:

    $ git clone 
    $ cd bilitw
    $ autoreconf -fvi
    $ ./configure  CFLAGS="-DGRACEFUL" --enable-debug=full
    $ make
    $ make install
    $ nohup bilitw -o /var/log/bilitw.log  -v 3 &

A quick checklist:

+ Use newer version of gcc (older version of gcc has problems)
+ Use CFLAGS="-O1" ./configure && make
+ Use CFLAGS="-O3 -fno-strict-aliasing" ./configure && make
+ `autoreconf -fvi && ./configure` needs `automake` and `libtool` to be installed


## Configuration
  Default under /etc/nutcracker.yml

    Graceful Reload Configuration:
    localhost:~:# ps -ef | grep bilitw
    root     19521 19227  0 19:22 pts/0    00:00:00 bilitw master
    root     19522 19521  0 19:22 pts/0    00:00:00 bilitw worker 0
    root     19523 19521  0 19:22 pts/0    00:00:00 bilitw worker 1
    kill -SIGHUP 19521

## Unit Test
  Dependency:
  yum install python
  yum install python-redis
  
  For Redis:
  ./tests/test.py

## Help
    $ bilitw -h
    Options:
    -h, --help             : this help
    -V, --version          : show version and exit
    -t, --test-conf        : test configuration for syntax errors and exit
    -d, --daemonize        : run as a daemon
    -D, --describe-stats   : print stats description and exit
    -v, --verbose=N        : set logging level (default: 5, min: 0, max: 11)
    -o, --output=S         : set logging file (default: stderr)
    -c, --conf-file=S      : set configuration file (default: /etc/nutcracker.yml)
    -s, --stats-port=N     : set stats monitoring port (default: 22223)
    -a, --stats-addr=S     : set stats monitoring ip (default: 0.0.0.0)
    -i, --stats-interval=N : set stats aggregation interval in msec (default: 30000 msec)
    -p, --pid-file=S       : set pid file (default: off)
    -m, --mbuf-size=N      : set size of mbuf chunk in bytes (default: 16384 bytes)
    -n, --worker-num=N     : set number of workers (default: number of cpu cores)
    -M, --core-mask=N      : set cpu core mask that worker process bind to
    
    bilitw -n 2 -M 12    
    // 2 means launch 2 workers
    // 12 means mask bitmap 0x1100, which tell 2 workers to bind on cpu 2 and cpu 3. 
    
    localhost:~:# ps -ef | grep bilitw
    root     19521 19227  0 19:22 pts/0    00:00:00 bilitw master
    root     19522 19521  0 19:22 pts/0    00:00:00 bilitw worker 0
    root     19523 19521  0 19:22 pts/0    00:00:00 bilitw worker 1
    
    [2015-12-21 19:20:15.247] nc_process.c:256 set worker 0 affinity to cpu core 2
    [2015-12-21 19:20:15.247] nc_process.c:256 set worker 1 affinity to cpu core 3

## Observability

Observability in bilitw is through logs and stats.

    $ bilitw --describe-stats

    pool stats:
      client_eof          "# eof on client connections"
      client_err          "# errors on client connections"
      client_connections  "# active client connections"
      server_ejects       "# times backend server was ejected"
      forward_error       "# times we encountered a forwarding error"
      fragments           "# fragments created from a multi-vector request"

    server stats:
      server_eof          "# eof on server connections"
      server_err          "# errors on server connections"
      server_timedout     "# timeouts on server connections"
      server_connections  "# active server connections"
      requests            "# requests"
      request_bytes       "total request bytes"
      responses           "# responses"
      response_bytes      "total response bytes"
      in_queue            "# requests in incoming queue"
      in_queue_bytes      "current request bytes in incoming queue"
      out_queue           "# requests in outgoing queue"
      out_queue_bytes     "current request bytes in outgoing queue"

Logging in bilitw is only available when bilitw is built with logging enabled. By default logs are written to stderr. bilitw can also be configured to write logs to a specific file through the -o or --output command-line argument. 


## License
Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
