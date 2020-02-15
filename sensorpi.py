#!/usr/bin/env python

import os
import time
import json
import requests
import signal
import globalVars as gv
from scapy.all import *
import threading
from spmodule import *
import urllib3

# Disable certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Variables
scanWLAN = 'Aironet-NTS-Secure'
            
# Read WLANs from file
wlans = readConfig(gv.wlansFile)

# Check if requested WLAN is stored already
if scanWLAN in wlans.keys():
    # System preparation
    changeIfaceMode(gv.iface)            
    scanWLANChannels = []
    for wlanInfo in wlans[scanWLAN]:
        gv.scanWLANBSSIDs.append(wlanInfo['bssid'])
        scanWLANChannels.append(wlanInfo['channel'])

    logging.info('Start scanning on channels ' + str(scanWLANChannels) + ' for WLAN ' + scanWLAN)
    logging.info('Scanning every channel for ' + gv.channelTime + ' seconds')
    logging.info('Sending data to Splunk in bulks of %s' %gv.splunkBulk)

    try:    
        while 1:
            for scanWLANChannel in scanWLANChannels:
                logging.info('Setting interface to channel %s'%scanWLANChannel)
                os.system("iwconfig " + gv.iface + " channel " + str(scanWLANChannel))
                loopTime = time.time() + int(gv.channelTime)
                while time.time() < loopTime:
                    sniff(iface=gv.iface, prn=data, count=10, timeout=3, store=0)
    except KeyboardInterrupt:
        print("W: interrupt received, stopping")

else:
    logging.error('WLAN %s not found in list, please scan first.' %scanWLAN)

