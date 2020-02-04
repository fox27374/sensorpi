#!/usr/bin/python

import os
import time
import json
import requests
from scapy.all import *
import threading
from spmodule import *
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def data(pkt):
    global frameTypes
    global scanWLANBSSIDs
    global pkts
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
        pktTime = time.time() #Epoch time for Splunk HEC

        #pktChannel = int(ord(pkt[Dot11Elt:3].info))
        pktChannel = pkt[RadioTap].Channel
        if pktType == 0:
            pktSSID = pkt[Dot11Elt].info
            pktSSID = pktSSID.decode('UTF-8')
        else:
            pktSSID = 'NA'

        pktInfo = {"time":pktTime, "event":{"type":pktType, "subtype":pktSubtype, "tods":pktToDS, "fromds":pktFromDS, "ssid":pktSSID, "bssid":pktBSSID, "channel":pktChannel, "retry":pktRetry}}
        if len(pkts) <= int(splunkBulk):
            pkts.append(pktInfo)
        else:
            sendThread = threading.Thread(target=sendData, args=(pkts, splunkServer, splunkPort, splunkURL, splunkToken))
            sendThread.start()
            pkts = []
            pkts.append(pktInfo)

# Load Configuration
configFile = 'config.json'
frameTypesFile = 'frametypes.json'

sensorPiConfig = readConfig(configFile)
frameTypes = readConfig(frameTypesFile)

logging.info('Reading config file %s'%configFile)
logging.info('Starting SensorPi with this configuration:')
logging.info(sensorPiConfig)

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
    changeIfaceMode(iface)            
    scanWLANBSSIDs = []
    scanWLANChannels = []
    for wlanInfo in wlans[scanWLAN]:
        scanWLANBSSIDs.append(wlanInfo['bssid'])
        scanWLANChannels.append(wlanInfo['channel'])

    logging.info('Start scanning on channels ' + str(scanWLANChannels) + ' for WLAN ' + scanWLAN)
    logging.info('Scanning every channel for ' + channelTime + ' seconds')
    logging.info('Sending data to Splunk in bulks of %s' %splunkBulk)

    while 1:
        for scanWLANChannel in scanWLANChannels:
            logging.info('Setting interface to channel %s'%scanWLANChannel)
            os.system("iwconfig " + iface + " channel " + str(scanWLANChannel))
            loopTime = time.time() + int(channelTime)
            while time.time() < loopTime:
                sniff(iface=iface, prn=data, count=10, timeout=3, store=0)

else:
    logging.error('WLAN %s not found in list, please scan first.' %scanWLAN)

