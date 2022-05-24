
# -*- coding: utf8 -*-
import json
import platform, os
import time, telnetlib
import socket

def port_check(HOST, port):
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   try:
      s.connect((HOST, int(port)))
      s.shutdown(1)
      print("Connected")
      return True
   except:
      print("Not Connected") 
      return False


def main_handler(event, context):
    print("Received event: " + json.dumps(event)) 
    print("Received context: " + str(context))
    
    return port_check(event['host'], event['port'])
