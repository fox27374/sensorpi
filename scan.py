#!/usr/bin/env python

import os
import json
import time
from scapy.all import *
from splib import *

# Load Configuration
configFile = 'config.json'
sensorPiConfig = readConfig(configFile)

# SensorPi
iface = sensorPiConfig['SensorPi']['Interface']
#channels = sensorPiConfig['SensorPi']['Channels']
scanTime = sensorPiConfig['SensorPi']['Scantime']
wlansFile = sensorPiConfig['SensorPi']['wlansFile']

# Variables
channels= [1,6,11,36,40,44,48]

# System preparation
changeIfaceMode(iface)            
            
logging.info('Scanning for %s seconds to get all WLANs on channels %s'%(scanTime, channels))
loopTime = time.time() + int(scanTime)
while time.time() < loopTime:
    for channel in channels:
        os.system("iwconfig " + iface + " channel " + str(channel))
        sniff(iface=iface, prn=beacon, count=10, timeout=1, store=0)

