#! /usr/bin/env python
#coding=utf-8
import json
import sys


class Server:
	svrCount = 0
	def __init__(self, raw):
	  self.raw = raw
	  Server.svrCount += 1

class ServerPool:
   spCount = 0
   	
   def __init__(self, raw):
      self.raw = raw
      ServerPool.spCount += 1
   
class Worker:
	wkCount = 0
	
	def __init__(self, raw):
	  self.raw = raw
	  Worker.wkCount += 1
		 
	def parse(self):
		
	  self.cur_connections = 1,
      self.service = self.raw['service']
      self.source = self.raw['source']
      self.timstamp = self.raw['timestamp']
      self.total_connections += self.raw['total_connections']
      self.uptime = self.raw['uptime']
      
    "uptime": 1192,
    "version": "0.4.1"
  	


while 1:
    line = sys.stdin.readline()
    if not line:
        break
			
    # parse to json
    parsed_data =  json.loads(line[:-1])

 parsed_data

Woker

print parsed_data['version']




