#!/usr/bin/python

import os
import json
import time
from scapy.all import *
from spmodule import *

def beacon(pkt):
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info
        bssid = pkt[Dot11].addr3    
        channel = int(ord(pkt[Dot11Elt:3].info))
        wlan = {'ssid':ssid.decode('UTF-8'), 'bssid':bssid, 'channel':channel}
        createWlanList(wlan, wlans)

# Load Configuration
configFile = 'config.json'
sensorPiConfig = readConfig(configFile)

# SensorPi
iface = sensorPiConfig['SensorPi']['Interface']
channels = sensorPiConfig['SensorPi']['Channels']
scanTime = sensorPiConfig['SensorPi']['Scantime']
wlansFile = sensorPiConfig['SensorPi']['wlansFile']

# Variables
wlans = {}

# System preparation
changeIfaceMode(iface)            
            
print('Scanning for %s seconds to get all WLANs on channels %s'%(scanTime, channels))
loopTime = time.time() + int(scanTime)
while time.time() < loopTime:
    for channel in channels:
        os.system("iwconfig " + iface + " channel " + str(channel))
        sniff(iface=iface, prn=beacon, count=10, timeout=1, store=0)

writeWlanList(wlansFile, wlans)
