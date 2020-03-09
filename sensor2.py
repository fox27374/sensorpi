#!/usr/bin/env python

import subprocess as sp
import json
import globalVars as gv
from splib import *
import paho.mqtt.client as mqtt

scanWLANSSID = str(sys.argv[1])
wlans = readConfig('wlans.json')
scanWLANChannels = []
scanWLANBSSIDs = []
for wlanInfo in wlans[scanWLANSSID]:
    scanWLANBSSIDs.append(wlanInfo['bssid'])
    scanWLANChannels.append(wlanInfo['channel'])

def mqttSend(data):
    brokerAddress=gv.mqttServer
    client = mqtt.Client('sensor')
    client.connect(brokerAddress)
    client.publish("sensorpi/sensordata", data)


def run_command(cmd):
    procSensor = sp.Popen(cmd, stdout=sp.PIPE)
    while True:
        output = procSensor.stdout.readline()
        if output == '' and procSensor.poll() is not None:
            break
        if output:
            printOutput = output.strip().decode()
            # Filter pkt header line that is send by TShark
            if 'index' not in printOutput:
                pktRaw = json.loads(output.strip())
                pktTime = pktRaw['timestamp']
                pktTypeRaw = pktRaw['layers']['wlan_fc_type'][0]
                pktType = gv.frameTypes[pktTypeRaw]['Name']
                pktSubtypeRaw = pktRaw['layers']['wlan_fc_subtype'][0]
                pktSubtype = gv.frameTypes[pktTypeRaw][pktSubtypeRaw]
                pktSSID = 'NA'
                if 'wlan_ssid' in pktRaw['layers'].keys(): pktSSID = pktRaw['layers']['wlan_ssid'][0]
                pktBSSID = pktRaw['layers']['wlan_bssid'][0]
                pktRetry = pktRaw['layers']['wlan_fc_retry'][0]
                pktSource = pktRaw['layers']['wlan_sa'][0]
                pktDestination = pktRaw['layers']['wlan_da'][0]
                pktChannel = pktRaw['layers']['wlan_radio_channel'][0]
                pktInfo = {"time":pktTime, "event":{"type":pktType, "subtype":pktSubtype, "ssid":pktSSID, "bssid":pktBSSID, "source":pktSource, "destination":pktDestination, "channel":pktChannel, "retry":pktRetry}}            
                mqttSend(json.dumps(pktInfo))
    rc = process.poll()

cmdFilter = ['-Y', 'wlan.bssid==' + scanWLANBSSIDs[0] + ' or wlan.sa==' + scanWLANBSSIDs[0] + ' or wlan.da==' + scanWLANBSSIDs[0]]
cmd = 'tshark -i ' + gv.iface + ' -l -e wlan.fc.retry -e wlan.fc.type -e wlan.fc.subtype -e wlan.bssid -e wlan.ssid -e wlan.sa -e wlan.da -e wlan_radio.channel -s 100 -T ek'
cmd = cmd.split(' ')
cmd += cmdFilter
print(cmd)

run_command(cmd)


