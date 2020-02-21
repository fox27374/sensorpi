#!/usr/bin/env python

import signal
import globalVars as gv
from scapy.all import *
from splib import *
import subprocess as sp


scriptScan = 'scan.py'
scriptSensor = 'sensor.py'
scriptLogger = 'logger.py'
scriptForwarder = 'forwarder.py'

# Disable certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Variables
scanWLAN = 'Aironet-NTS-Secure'

# Read WLANs from file
wlans = readConfig(gv.wlansFile)

# Start Logging
procLogger = sp.Popen(['python', scriptLogger])
mqttLog('Starting logger subprocess with PID: %s' %procLogger.pid)

# Start Forwarder
procForwarder = sp.Popen(['python', scriptForwarder])
mqttLog('Starting forwarder subprocess with PID: %s' %procForwarder.pid)

# Get BSSIDs and channels from SSID
try:
    if scanWLAN in wlans.keys():
        for wlanInfo in wlans[scanWLAN]:
            gv.scanWLANBSSIDs.append(wlanInfo['bssid'])
            gv.scanWLANChannels.append(wlanInfo['channel'])
        procSensor = sp.Popen(['python', scriptSensor, scanWLAN], stdout=sp.PIPE, stderr=sp.PIPE)
        mqttLog('Starting sensor subprocess with PID: %s' %procSensor.pid)
        procSensorReturn = procSensor.communicate()

    else:
        mqttLog('SSID %s not in WLAN list. Start scanning' %scanWLAN)
        procScan = sp.Popen(['python', scriptScan], stdout=sp.PIPE, stderr=sp.PIPE)
        procScanReturn = procScan.communicate()

except KeyboardInterrupt:
        mqttLog('Interrupt received, exiting')

finally:
        mqttLog('Stopping sensor subprocess with PID: %s' %procSensor.pid)
        procSensor.terminate()
        mqttLog('Stopping forwarder subprocess with PID: %s' %procForwarder.pid)
        procForwarder.terminate()
        mqttLog('Stopping logger subprocess with PID: %s' %procSensor.pid)
        procLogger.terminate()


