#!/usr/bin/python

import os
import time
import json
import requests
from datetime import datetime
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
        ap = pkt.addr2
        ssid = pkt[Dot11Elt].info
        bssid = pkt[Dot11].addr3    
        channel = int(ord(pkt[Dot11Elt:3].info))
        wlan = {'SSID':ssid.decode('UTF-8'), 'AP':ap, 'BSSID':bssid, 'CHANNEL':channel}
        createWlanList(wlan)

def data(pkt):
    global frameTypes
    pktRetry = False
    pktToDS = False
    pktFromDS = False

    pktBSSID = pkt[Dot11].addr3
    pktRetry = pkt[Dot11].FCfield.retry != 0
    pktType = frameTypes[str(pkt.type)]['Name']
    pktSubtype = frameTypes[str(pkt.type)][str(pkt.subtype)]
    pktTime = datetime.now().isoformat()


    # Get ToDS and FromDS flags if packet is of type data
    # and read BSSID from a different address field
    if pkt.type == 2:
        pktToDS = pkt.FCfield & 0x4 != 0
        pktFromDS = pkt.FCfield & 0x5 != 0
        if pktToDS: pktBSSID = pkt[Dot11].addr1
        if pktFromDS: pktBSSID = pkt[Dot11].addr2

    #pktChannel = int(ord(pkt[Dot11Elt:3].info))
    pktChannel = pkt[RadioTap].Channel
    if pktType == 0:
        pktSSID = pkt[Dot11Elt].info
        pktSSID = pktSSID.decode('UTF-8')
    else:
        pktSSID = 'NA'

    pktInfo = {"event":{"time":str(pktTime), "type":pktType, "subtype":pktSubtype, "tods":pktToDS, "fromds":pktFromDS, "ssid":pktSSID, "bssid":pktBSSID, "channel":pktChannel, "retry":pktRetry}}
    aggregateData(pktInfo)


def aggregateData(pktInfo):
    global pkts
    if len(pkts) <= 100:
        pkts.append(pktInfo)
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

# Load Configuration
configFile = 'config.json'
frameTypesFile = 'frametypes.json'

sensorPiConfig = readConfig(configFile)
frameTypes = readConfig(frameTypesFile)

# SensorPi
iface = sensorPiConfig['SensorPi']['Interface']
channels = sensorPiConfig['SensorPi']['Channels']
scanTime = sensorPiConfig['SensorPi']['Scantime']
# Splunk
splunkServer = sensorPiConfig['Splunk']['Server']
splunkPort = sensorPiConfig['Splunk']['Port']
splunkURL = sensorPiConfig['Splunk']['URL']
splunkToken = sensorPiConfig['Splunk']['Token']

# Variables
wlans = {}
pkts = []

# System preparation
changeIfaceMode(iface)            
            
print('Scanning for %s seconds to get all WLANs on channels %s'%(scanTime, channels))
loopTime = time.time() + scanTime
#while time.time() < loopTime:

#os.system("iwconfig " + iface + " channel " + str(channel))
os.system("iwconfig " + iface + " channel " + str(1))
while 1:
    #for channel in channels:
    #sniff(iface=iface, prn=beacon, count=10, timeout=3, store=0)
    sniff(iface=iface, prn=data, count=10, timeout=3, store=0)

