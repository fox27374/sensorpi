#!/usr/bin/env python

import os
import time
import json
import requests
import signal
import globalVars as gv
from scapy.all import *
import threading
from splib import *
import urllib3
import subprocess as sp


scriptScan = 'scan.py'
scriptSensor = 'sensor.py'

# Disable certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Variables
scanWLAN = 'Aironet-NTS-Secure'

# Read WLANs from file
wlans = readConfig(gv.wlansFile)

# Get BSSIDs and channels from SSID
try:
    if scanWLAN in wlans.keys():
        for wlanInfo in wlans[scanWLAN]:
            gv.scanWLANBSSIDs.append(wlanInfo['bssid'])
            gv.scanWLANChannels.append(wlanInfo['channel'])
        procSensor = sp.Popen(['python', scriptSensor, scanWLAN], stdout=sp.PIPE, stderr=sp.PIPE)
        logging.info('Starting sensor subprocess with PID: %s' %procSensor.pid)
        procSensorReturn = procSensor.communicate()

    else:
        logging.info('SSID %s not in WLAN list. Start scanning' %scanWLAN)
        procScan = sp.Popen(['python', scriptScan], stdout=sp.PIPE, stderr=sp.PIPE)
        procScanReturn = procScan.communicate()

except KeyboardInterrupt:
        logging.info('Interrupt received, exiting')

finally:
        logging.info('Stopping sensor subprocess with PID: %s' %procSensor.pid)
        procSensor.terminate()


