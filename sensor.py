#!/usr/bin/env python

import subprocess as sp
import json
import globalVars as gv
from splib import *
import paho.mqtt.client as mqtt


# Read Channels and BSSIDs from file
# Filter by SSID that is passed from the main process
scanWLANSSID = str(sys.argv[1])
wlans = readConfig('wlans.json')
scanWLANChannels = []
scanWLANBSSIDs = []
for wlanInfo in wlans[scanWLANSSID]:
    scanWLANBSSIDs.append(wlanInfo['bssid'])
    scanWLANChannels.append(wlanInfo['channel'])

# Remove duplicates
scanWLANChannels = list(dict.fromkeys(scanWLANChannels))

def mqttSend(data):
    brokerAddress=gv.mqttServer
    client = mqtt.Client('sensor')
    client.connect(brokerAddress)
    client.publish("sensorpi/sensordata", data)


def sensor(cmd):
    procSensor = sp.Popen(cmd, stdout=sp.PIPE)
    mqttLog('Starting TShark subprocess with PID: %s' %procSensor.pid)
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
                pktSSID = pktBSSID = pktSA = pktDA = pktTA = pktRA = 'NA'
                pktRetry = 'False'
                if 'wlan_ssid' in pktRaw['layers'].keys(): pktSSID = pktRaw['layers']['wlan_ssid'][0]
                if 'wlan_bssid' in pktRaw['layers'].keys(): pktBSSID = pktRaw['layers']['wlan_bssid'][0]
                if 'wlan_sa' in pktRaw['layers'].keys(): pktSA = pktRaw['layers']['wlan_sa'][0]
                if 'wlan_da' in pktRaw['layers'].keys(): pktDA = pktRaw['layers']['wlan_da'][0]
                if 'wlan_ta' in pktRaw['layers'].keys(): pktTA = pktRaw['layers']['wlan_ta'][0]
                if 'wlan_ra' in pktRaw['layers'].keys(): pktRA = pktRaw['layers']['wlan_ra'][0]
                if pktRaw['layers']['wlan_fc_retry'][0] == '1': pktRetry = 'True'
                pktChannel = pktRaw['layers']['wlan_radio_channel'][0]
                pktDuration = int(pktRaw['layers']['wlan_radio_duration'][0]) + int(pktRaw['layers']['wlan_radio_preamble'][0])
                pktInfo = {"time":pktTime, "event":{"Type":pktType, "Subtype":pktSubtype, "SSID":pktSSID, "BSSID":pktBSSID, "SA":pktSA, "DA":pktDA, "TA":pktTA, "RA":pktRA, "Duration":pktDuration, "Channel":pktChannel, "Retry":pktRetry}}            
                mqttSend(json.dumps(pktInfo))

cmdFilter = ['-Y', 'wlan.ta==' + scanWLANBSSIDs[0] + ' or wlan.ra==' + scanWLANBSSIDs[0] + ' or wlan.sa==' + scanWLANBSSIDs[0]]
cmd = 'tshark -i ' + gv.iface + ' -l -e wlan.fc.retry -e wlan.fc.type -e wlan.fc.subtype -e wlan.bssid -e wlan.ssid -e wlan.sa -e wlan.da -e wlan.ta -e wlan.ra -e wlan_radio.duration -e wlan_radio.preamble -e wlan_radio.channel -s 100 -T ek'
cmd = cmd.split(' ')
cmd += cmdFilter

# Logging some info
mqttLog('Starting sensor for SSID: %s' %scanWLANSSID)
mqttLog('Channels for this SSID: %s' %scanWLANChannels)
mqttLog('BSSIDs for this SSID: %s' %scanWLANBSSIDs)
mqttLog('Changing channel every %s seconds' %gv.channelTime)
mqttLog('TShark filter: %s' %cmdFilter)

# Start sensor loop
sensor(cmd)


