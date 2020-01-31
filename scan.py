#!/usr/bin/python

import os
import json
import time
from scapy.all import *


def readConfig(configFile):
    with open(configFile, 'r') as cf:
        configDict = json.load(cf)
    return configDict

def changeIfaceMode(iface):
    os.system("ifconfig " + iface + " down") 
    os.system("iwconfig " + iface + " mode monitor")
    os.system("ifconfig " + iface + " up") 

def beacon(pkt):
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info
        bssid = pkt[Dot11].addr3    
        channel = int(ord(pkt[Dot11Elt:3].info))
        wlan = {'ssid':ssid.decode('UTF-8'), 'bssid':bssid, 'channel':channel}
        createWlanList(wlan)

def createWlanList(wlan):
    ssid = wlan['ssid']
    bssid = wlan['bssid']
    wlanValue = {'bssid':bssid, 'channel':wlan['channel']}
    addValue = True
    
    # Append values if SSID exists (no duplicates)
    if ssid in wlans.keys():
        for a in wlans[ssid]:
            if a['bssid'] == bssid:
                addValue = False
        if addValue == True:
            wlans[ssid].append(wlanValue)

    # Add new SSID
    else:
        valueList = []
        valueList.append(wlanValue)
        wlans[ssid] = valueList

def writeWlanList(wlansFile):
    f = open(wlansFile, 'w')
    f.write(json.dumps(wlans, indent=4))
    f.close()

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

writeWlanList(wlansFile)
