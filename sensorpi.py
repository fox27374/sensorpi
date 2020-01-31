#!/usr/bin/python

import os
import time
import json
import requests
from datetime import datetime
from scapy.all import *
from spmodule import *


def data(pkt):
    global frameTypes
    global scanWLANBSSIDs
    pktRetry = False
    pktToDS = False
    pktFromDS = False
    pktBSSID = pkt[Dot11].addr3
    # Get ToDS and FromDS flags if packet is of type data
    # and read BSSID from a different address field
    if pkt.type == 2:
        pktToDS = pkt.FCfield & 0x4 != 0
        pktFromDS = pkt.FCfield & 0x5 != 0
        if pktToDS: pktBSSID = pkt[Dot11].addr1
        if pktFromDS: pktBSSID = pkt[Dot11].addr2
    # Check if BSSID is in one of the addres fields
    # otherwise the frame is not interresting
    if pktBSSID in scanWLANBSSIDs:
        pktRetry = pkt[Dot11].FCfield.retry != 0
        pktType = frameTypes[str(pkt.type)]['Name']
        pktSubtype = frameTypes[str(pkt.type)][str(pkt.subtype)]
        pktTime = datetime.now().isoformat()

        #pktChannel = int(ord(pkt[Dot11Elt:3].info))
        pktChannel = pkt[RadioTap].Channel
        if pktType == 0:
            pktSSID = pkt[Dot11Elt].info
            pktSSID = pktSSID.decode('UTF-8')
        else:
            pktSSID = 'NA'

        pktInfo = {"event":{"time":str(pktTime), "type":pktType, "subtype":pktSubtype, "tods":pktToDS, "fromds":pktFromDS, "ssid":pktSSID, "bssid":pktBSSID, "channel":pktChannel, "retry":pktRetry}}
        aggregateData(pktInfo, pkts, splunkServer, splunkPort, splunkURL, splunkToken, splunkBulk)


# Load Configuration
configFile = 'config.json'
frameTypesFile = 'frametypes.json'

sensorPiConfig = readConfig(configFile)
frameTypes = readConfig(frameTypesFile)

# SensorPi
iface = sensorPiConfig['SensorPi']['Interface']
channels = sensorPiConfig['SensorPi']['Channels']
scanTime = sensorPiConfig['SensorPi']['Scantime']
channelTime = sensorPiConfig['SensorPi']['Channeltime']
wlansFile = sensorPiConfig['SensorPi']['wlansFile']
frameTypesFile = sensorPiConfig['SensorPi']['frameTypesFile']
# Splunk
splunkServer = sensorPiConfig['Splunk']['Server']
splunkPort = sensorPiConfig['Splunk']['Port']
splunkURL = sensorPiConfig['Splunk']['URL']
splunkToken = sensorPiConfig['Splunk']['Token']
splunkBulk = sensorPiConfig['Splunk']['Bulk']

# Variables
scanWLAN = 'Aironet-NTS-Secure'
pkts = []
            
# Read WLANs from file
wlans = readConfig(wlansFile)

# Check if requested WLAN is stored already
if scanWLAN in wlans.keys():
    # System preparation
    print('Setting interface %s to monitor mode' %iface)
    changeIfaceMode(iface)            
    scanWLANBSSIDs = []
    scanWLANChannels = []
    for wlanInfo in wlans[scanWLAN]:
        scanWLANBSSIDs.append(wlanInfo['bssid'])
        scanWLANChannels.append(wlanInfo['channel'])

    print('Start scanning on channels ' + str(scanWLANChannels) + ' for WLAN ' + scanWLAN)
    print('Scanning every channel for ' + channelTime + ' seconds')
    print('Sending data to Splunk in bulks of %s' %splunkBulk)

    while 1:
        for scanWLANChannel in scanWLANChannels:
            os.system("iwconfig " + iface + " channel " + str(scanWLANChannel))
            loopTime = time.time() + int(channelTime)
            while time.time() < loopTime:
                sniff(iface=iface, prn=data, count=10, timeout=3, store=0)

else:
    print('WLAN %s not found in list, please scan first.' %scanWLAN)

