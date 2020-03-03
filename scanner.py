#!/usr/bin/env python

import os
import time
import globalVars as gv
from scapy.all import sniff
from splib import beacon, changeIfaceMode, mqttLog

# Variables
channels= [1,6,11,36,40,44,48]

# System preparation
changeIfaceMode(gv.iface)

mqttLog('Scanning for %s seconds to get all WLANs on channels %s' %(gv.scanTime, channels))
mqttLog('Ignoring WLANs with a RSSI beneath -%sdBm' %(gv.rssiThreshold))
#logging.info('Scanning for %s seconds to get all WLANs on channels %s'%(gv.scanTime, channels))
loopTime = time.time() + int(gv.scanTime)
while time.time() < loopTime:
    for channel in channels:
        os.system("iwconfig " + gv.iface + " channel " + str(channel))
        sniff(iface=gv.iface, prn=beacon, count=10, timeout=1, store=0)

