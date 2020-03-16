#!/usr/bin/env python

import os
from time import sleep
import globalVars as gv
import subprocess as sp
from splib import changeIfaceMode, mqttLog

# Variables
clientID = 'scanner'
scriptScanner = 'tshark.py'
scriptWriter = 'writer.py'
channels= [1,6,11,36,40,44,48]
#channels= [40,44,48,52,56]

# System preparation
changeIfaceMode(gv.iface)

# Start Scanner
procScanner = sp.Popen(['python', scriptScanner])
mqttLog(clientID, 'Starting scanner subprocess with PID: %s' %procScanner.pid)


try:
    procWriter = sp.Popen(['python', scriptWriter])
    mqttLog(clientID, 'Starting writer subprocess with PID: %s' %procWriter.pid)
    
    for channel in channels:
        os.system("iwconfig " + gv.iface + " channel " + str(channel))
        mqttLog(clientID, 'Changing interface channel to: %s' %channel)
        sleep(int(gv.scanTime))

    mqttLog(clientID, 'Stopping scanner subprocess with PID: %s' %procScanner.pid)
    procScanner.terminate()
    mqttLog(clientID, 'Stopping writer subprocess with PID: %s' %procWriter.pid)
    procWriter.terminate()

except KeyboardInterrupt:
    mqttLog(clientID, 'Interrupt received, exiting')

finally:
    mqttLog(clientID, 'Stopping scanner subprocess with PID: %s' %procScanner.pid)
    procScanner.terminate()
    mqttLog(clientID, 'Stopping writer subprocess with PID: %s' %procWriter.pid)
    procWriter.terminate()
