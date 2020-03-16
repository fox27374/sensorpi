#!/usr/bin/env python

import globalVars as gv
import subprocess as sp
from json import loads, dumps
from splib import mqttSend, mqttLog
import signal

# Variables
clientID = 'TShark'

def tshark(cmd):
    procTshark = sp.Popen(cmd, stdout=sp.PIPE)
    mqttLog(clientID, 'Starting tshark subprocess with PID: %s' %procTshark.pid)    

    try:
        while True:
            output = procTshark.stdout.readline()
            if output == '' and procTshark.poll() is not None:
                break
            if output:
                printOutput = output.strip().decode()
                if 'index' not in printOutput:
                    # Filter pkt header line that is send by TShark
                    pktRaw = loads(output.strip())
                    pktSSID = pktRaw['layers']['wlan_ssid'][0]
                    pktBSSID = pktRaw['layers']['wlan_bssid'][0]
                    pktChannel = pktRaw['layers']['wlan_radio_channel'][0]
                    pktInfo = {"ssid":pktSSID, "bssid":pktBSSID, "channel":pktChannel}            
                    mqttSend(clientID, dumps(pktInfo))
    except:
        mqttLog(clientID, 'Stopping tshark subprocess with PID: %s' %procTshark.pid)
        procTshark.terminate()

cmdFilter = ['-Y', 'wlan.fc.type==0 and wlan.fc.subtype==8']
cmd = 'tshark -i ' + gv.iface + ' -l -e wlan.ssid -e wlan.bssid -e wlan_radio.channel -s 100 -Tek'
mqttLog(clientID, 'TShark command: %s' %cmd)
mqttLog(clientID, 'TShark filter: %s' %cmdFilter)
cmd = cmd.split(' ')
cmd += cmdFilter

# Start TShark
tshark(cmd)

