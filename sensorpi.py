#!/usr/bin/python

import os
import time
import json
import requests
from datetime import datetime
from scapy.all import *

# Configuration
scanTime = 10

# Variables
wlans = {}
pkts = []

if len(sys.argv) ==  2:
    iface = str(sys.argv[1])
else:
    iface = "wlan0"

os.system("ifconfig " + iface + " down") 
os.system("iwconfig " + iface + " mode monitor")
os.system("ifconfig " + iface + " up")


def readConfig(configFile):
    with open(configFile, 'r') as cf:
        configDict = json.load(cf)
    return configDict


def beacon(pkt):
    if pkt.haslayer(Dot11Beacon):
        ap = pkt.addr2
        ssid = pkt[Dot11Elt].info
        bssid = pkt[Dot11].addr3    
        channel = int(ord(pkt[Dot11Elt:3].info))
        wlan = {'SSID':ssid.decode('UTF-8'), 'AP':ap, 'BSSID':bssid, 'CHANNEL':channel}
        createWlanList(wlan)

def data(pkt):
    pktRetry = '0'
    if 'retry' in pkt.FCfield:
        pktRetry = '1'
    if pkt.type == 0: pktType = 'Management'
    if pkt.type == 1: pktType = 'Control'
    if pkt.type == 2: pktType = 'Data'

    pktBSSID = pkt[Dot11].addr3
    pktSubtype = pkt.subtype
    pktTime = datetime.now().isoformat()
    #pktChannel = int(ord(pkt[Dot11Elt:3].info))
    pktChannel = pkt[RadioTap].Channel
    if pktType == 0:
        pktSSID = pkt[Dot11Elt].info
        pktSSID = pktSSID.decode('UTF-8')
    else:
        pktSSID = 'NA'

    pktInfo = {"event":{"time":str(pktTime), "type":pktType, "subtype":pktSubtype, "ssid":pktSSID, "bssid":pktBSSID, "channel":pktChannel, "flags":{"retry":pktRetry}}}

    #print(pktTime)
    aggregateData(pktInfo)
    #print(json.dumps(pktInfo, indent=4))
    #sendData('172.24.89.171', 'b6b02802-eaf6-4d17-89b1-0fd6d66d2673', pktInfo)


def aggregateData(pktInfo):
    global pkts
    if len(pkts) <= 100:
        pkts.append(pktInfo)
        #print(pkts)
    else:
        sendData(pkts)
        pkts = []
        pkts.append(pktInfo)

def sendData(pkts):
    url = 'https://' + splunkServer + ':' + splunkPort + splunkURL
    authHeader = {'Authorization': 'Splunk %s'%splunkToken}
    req = requests.post(url, headers=authHeader, json=pkts, verify=False)

def createWlanList(wlan):
    ssid = wlan['SSID']
    ap = wlan['AP']
    channel = wlan['CHANNEL']
    wlanValue = {'AP':ap, 'CHANNEL':channel}
    addValue = True
    
    # Append values if SSID exists (no duplicates)
    if ssid in wlans.keys():
        for a in wlans[ssid]:
            if a['AP'] == ap:
                addValue = False
        if addValue == True:
            wlans[ssid].append(wlanValue)

    # Add new SSID
    else:
        valueList = []
        valueList.append(wlanValue)
        wlans[ssid] = valueList

# Configuration
sensorPiConfig = readConfig('config.json')
channels = sensorPiConfig['SensorPi']['Channels']
splunkServer = sensorPiConfig['Splunk']['Server']
splunkPort = sensorPiConfig['Splunk']['Port']
splunkURL = sensorPiConfig['Splunk']['URL']
splunkToken = sensorPiConfig['Splunk']['Token']


print('Scanning for %s seconds to get all WLANs on channels %s'%(scanTime, channels))
loopTime = time.time() + scanTime
#while time.time() < loopTime:

#os.system("iwconfig " + iface + " channel " + str(channel))
os.system("iwconfig " + iface + " channel " + str(1))
while 1:
    #for channel in channels:
    #sniff(iface=iface, prn=beacon, count=10, timeout=3, store=0)
    sniff(iface=iface, prn=data, count=10, timeout=3, store=0)

#sendData(json.dumps(wlans))
#print(json.dumps(wlans, indent=4))
