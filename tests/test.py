#! /usr/bin/env python 
#coding=utf-8 
import redis 
print redis.__file__ 



print '#'*20 
print '#'*20 
print '#'*20 
print 'TESTING REDIS COMMAND'
print 'VIA BILIBILI TW'
print '#'*20 
print '#'*20 
print '#'*20 
print ' '*20 
print ' '*20 

r = redis.Redis(host='127.0.0.1', port=22121)
 
print '-'*20 
print 'STRING SUITE BEGIN'
print '-'*20 

r.set('c2','hello') 
if r.get('c2')!='hello':
  raise "get set case error"
print "get set done"

r.append('c2', ' world')
if r.get('c2')!='hello world':
  raise "append case error"
print "append case done"

r.set('c2', 'foobar')
if r.bitcount('c2')!=26:
  raise "bitcount case error"
print "bitcount case done"

r.set('c2', 10)
r.decr('c2')
if r.get('c2')!='9':
  raise "decr case error"
print "decr case done"

#python-redis not supported
#r.set('c2', 10)
#r.decrby ('c2', 5)
#if r.get('c2')!='5':
#  raise "decrby case error"

r.setbit('c2', 7, 1)
if r.getbit('c2', 7)!=1:
  raise "setbit, getbit case error"
print "setbit, getbit case done"

r.set('c2', 'This is a string')
if r.getrange('c2', 0, 3)!='This':
  raise "getrange case error"
print "getrange case done"

r.set('c3', '1')
if r.getset('c3','0')!='1':
  raise "getset case error"
if r.get('c3')!='0':
  raise "getset case error"
print "getset case done"

r.set('c4', 0)
r.incr('c4')
if r.get('c4')!='1':
  raise "incr case error"
print "incr case done"

r.incrby('c4',1)
if r.get('c4')!='2':
  raise "incrby case error"
print "incrby case done"

r.incrbyfloat('c4','0.1')
if r.get('c4')!='2.1':
  raise "incrbyfloat case error"
print "incrbyfloat case done"

r.set('key1', 'hello')
r.set('key2', 'world')
arr = r.mget('key1','key2','nonexisting')
if arr[0]!='hello' or arr[1]!='world' or arr[2]!=None:
  raise "mget case error"
print "mget case done"

r.mset({'key1': "hello", 'key2': 'world'})
if r.get('key1')!='hello' or r.get('key2')!='world':
  raise "mset case error"
print "mset case done"


r.setex('c2', "hello", 10)
if r.ttl('c2')!=10:
  raise "setex, ttl case error"
print "setex case done"

if r.psetex('c2', 1000,'hello')!=1:
  raise "psetex case error"
print "psetex case done"

r.delete('tyson')
if r.setnx('tyson', "hello")!=1:
  raise "setnx case error"
if r.setnx('tyson', "world")!=0:
  raise "setnx case error"
if r.get('tyson')!='hello':
  raise "setnx case error"
print "setnx case done"


r.set('c2',"Hello world")
if r.strlen('c2')!=11:
  raise "strlen case error"
print "strlen case done"



print '-'*20 
print 'STRING SUITE SUCCESS'
print '-'*20 

print ' '*20 
print ' '*20 

print '-'*20 
print 'HASH SUITE BEGIN'
print '-'*20 


r.delete('f1')
r.hset('f1', 'c2', "hello")
if r.hget('f1', 'c2')!='hello':
  raise "hset hget case error"
print "hset hget case done"

r.hset('f1', 'c2', "hello")
r.hdel('f1', 'c2')
if r.hget('f1', 'c2'):
  raise "hdel case error"
print "hdel case done"

r.hset('f1', 'c2', "hello")
if r.hexists('f1', 'c2')!=1:
  raise "hexists case error"
print "hexists case done"


r.hset('f1', 'c2', "hello")
r.hset('f1', 'c3', "world")
b = r.hgetall('f1')
if b['c2']!='hello' or b['c3']!='world':
  raise "hgetall case error"
print "hgetall case done"

r.hset('f1', 'c2', "5")
if r.hincrby('f1', 'c2', "5") != 10:
  raise "hincrby case error"
print "hincrby case done"

r.hset('f1', 'c2', "5")
if r.hincrbyfloat('f1', 'c2', 0.5) != 5.5:
  raise "hincrbyfloat case error"
print "hincrbyfloat case done"

r.hset('f1', 'c2', "hello")
r.hset('f1', 'c3', "world")
b = r.hkeys('f1')
print "hkeys case done"
if r.hlen('f1'):
  print "hlen case done"
else:
  raise "hlen case error"



r.hmset('f1', {'c1':'tyson', 'c2':'hua'})
if r.hget('f1', 'c1')!='tyson' or r.hget('f1', 'c2')!='hua':
  raise "hmset case error"
print "hmset case done"


r.hdel('f1', 'c5')
if r.hsetnx('f1', 'c5', 'hello')!=1:
  raise "hsetnx case error"
if r.hsetnx('f1', 'c5', 'hello')!=0:
  raise "hsetnx case error"
print "hsetnx case done"

r.hset('f1', 'c2', "hello")
r.hset('f1', 'c3', "world")
if 'hello' not in r.hvals('f1'):
  raise "hvals case error"
if 'world' not in r.hvals('f1'):
  raise "hvals case error"
print "hvals case done"




print '-'*20 
print 'HASH SUITE SUCCESS'
print '-'*20 


print ' '*20 
print ' '*20 

print '-'*20 
print 'LIST SUITE BEGIN'
print '-'*20 


r.delete('f1')
r.lpush('f1',"hello")
r.lpush('f1',"world")
if r.lpop('f1')!='world':
  raise "lpush, lpop case error"
print "lpush, lpop case done"


r.delete('f1')
r.rpush('f1',"hello")
r.rpush('f1',"world")
r.rpush('f1',"tyson")
if r.rpop('f1')!='tyson':
  raise "rpush, rpop case error"
print "rpush, rpop case done"

if r.llen('f1')!=2:
  raise "llen case error"
print "llen case done"

r.lset('f1', 0, 'hello1')
if r.lpop('f1')!='hello1':
  raise "lset case error"
print "lset case done"

if r.lrem('f1', 'world')!=1:
  raise "lrem case error"
print "lrem case done"

r.delete('f1')
if r.rpushx('f1', 'world'):
  raise "rpushx case error"
if r.rpushx('f1', 'world')!=0:
  raise "rpushx case error"
if r.lpushx('f1', 'world')!=0:
  raise "lpushx case error"
print "lpushx case done"
print "rpushx case done"


r.delete('f1')
r.rpush('f1',"hello")
r.rpush('f1',"world")
r.rpush('f1',"tyson")
r.ltrim('f1',0,0)
if r.llen('f1')!=1:
  raise "ltrim case error"
print "ltrim case done"
if r.lindex('f1', 0)!='hello':
  raise "lindex case error"
print "lindex case done"



print '-'*20 
print 'LIST SUITE SUCCESS'
print '-'*20 

print ' '*20 
print ' '*20 

print '-'*20 
print 'SET SUITE BEGIN'
print '-'*20 

r.delete('f1')
r.sadd('f1','hello')
r.sadd('f1','world')
r.sadd('f1','tyson')
#print r.smembers('f1')
if 'hello' not in r.smembers('f1'):
  raise "sadd case error"
print "sadd case done"
print "smembers case done"

if r.scard('f1')!=3:
  raise "scard case error"
print "scard case done"

r.delete('f2')
r.sadd('f2', 'hello');
r.sadd('f2', 'world');
if 'tyson' not in r.sdiff('f1','f2'):
  raise "sdiff case error"
print "sdiff case done"


if 'hello' not in r.sinter('f1','f2'):
  raise "sinter case error"
print "sinter case done"

if 'hello' not in r.sunion('f1','f2'):
  raise "sunion case error"
print "sunion case done"

if r.spop('f1'):
  print "spop case done"
else:
  raise "spop case error"

if r.srandmember('f1'):
  print "srandmember case done"
else:
  raise "srandmember case error"

if r.srem('f2', 'hello'):
  print "srem case done"
else:
  raise "sren case error"


print '-'*20 
print 'SET SUITE SUCCESS'
print '-'*20 

print ' '*20 
print ' '*20 


print '-'*20 
print 'SORTED set SUITE BEGIN'
print '-'*20 

r.delete('f1')
r.delete('f2')
r.zadd('f1','one',1)
r.zadd('f1','two',2)
r.zadd('f1','three',3)
#print r.zrange('f1', 2, 3)
if 'three' not in r.zrange('f1',2,3):
  raise "zadd case error"
print "zadd case done"
print "zrange case done"



print '-'*20 
print 'SORTED SET SUITE SUCCESS'
print '-'*20 

print ' '*20 
print ' '*20 



print '#'*20 
print '#'*20 
print '#'*20 
print 'TESTING MEMCACHE COMMAND'
print 'VIA BILIBILI TW'
print '#'*20 
print '#'*20 
print '#'*20 
print ' '*20 
print ' '*20 

