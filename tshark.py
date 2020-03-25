#!/usr/bin/env python

import globalVars as gv
import subprocess as sp
import paho.mqtt.client as mqtt
from json import loads, dumps
from splib import mqttSend, mqttLog
import signal

# Variables
clientID = 'TShark'
runTshark = True

def mqttConnect(client, userdata, flags, rc):
    """Subscripe to MQTT topic"""
    mqttClient.subscribe('sensorpi/command')

def mqttMessage(client, userdata, msg):
    """Incoming MQTT message"""
    global runTshark
    msgDec = str(msg.payload)
    if 'stop' in msgDec:
        runTshark = False

def tshark(cmd):
    procTshark = sp.Popen(cmd, stdout=sp.PIPE)
    mqttLog(clientID, 'Starting tshark subprocess with PID: %s' %procTshark.pid)    

    try:
        while runTshark:
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
        else:
            mqttLog(clientID, 'Stopping tshark subprocess with PID: %s' %procTshark.pid)
            procTshark.terminate()

    except:
        mqttLog(clientID, 'Stopping tshark subprocess with PID: %s' %procTshark.pid)
        procTshark.terminate()

# Connect to MQTT server
mqttClient = mqtt.Client()
mqttClient.on_connect = mqttConnect
mqttClient.on_message = mqttMessage
mqttClient.connect(gv.mqttServer, int(gv.mqttPort), 60)

cmdFilter = ['-Y', 'wlan.fc.type==0 and wlan.fc.subtype==8']
cmd = 'tshark -i ' + gv.iface + ' -l -e wlan.ssid -e wlan.bssid -e wlan_radio.channel -s 100 -Tek'
mqttLog(clientID, 'TShark command: %s' %cmd)
mqttLog(clientID, 'TShark filter: %s' %cmdFilter)
cmd = cmd.split(' ')
cmd += cmdFilter

# Start TShark
try:
    mqttClient.loop_start()
    tshark(cmd)
except:
    mqttClient.disconnect()
    mqttLog(clientID, 'Stopping tshark subprocess with PID: %s' %procTshark.pid)
    procTshark.terminate()

