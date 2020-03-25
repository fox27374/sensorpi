#!/usr/bin/env python

import json
import os
import time
import requests
import globalVars as gv
from scapy.all import *
import logging
import urllib3
import paho.mqtt.client as mqtt

# set up logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename=gv.logFile,
                    filemode='a')
logging.getLogger("urllib3").setLevel(logging.WARNING)

# Disable certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def beacon(pkt):
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info
        bssid = pkt[Dot11].addr3
        #channel = int(ord(pkt[Dot11Elt:3].info))
        channel = pkt[RadioTap].Channel
        try:
            # convert RSSI to positive value
            rssi = abs(pkt.dBm_AntSignal)
        except:
            rssi = 100

        if rssi <= int(gv.rssiThreshold):
            wlan = {'ssid':ssid.decode('UTF-8'), 'bssid':bssid, 'channel':str(channel), 'rssi':rssi}
            createWlanList(wlan)

def mqttLog(clientID, data):
    brokerAddress = gv.mqttServer
    client = mqtt.Client(clientID)
    client.connect(brokerAddress)
    client.publish("sensorpi/log", data)

def mqttSend(clientID, data):
    brokerAddress=gv.mqttServer
    client = mqtt.Client(clientID)
    client.connect(brokerAddress)
    client.publish("sensorpi/sensordata", data)

def mqttCmd(clientID, module, cmd):
    data = module + '#' + cmd
    brokerAddress = gv.mqttServer
    mqttClient = mqtt.Client(clientID)
    mqttClient.connect(brokerAddress)
    mqttClient.publish("sensorpi/command", data)

def readConfig(configFile):
    with open(configFile, 'r') as cf:
        configDict = json.load(cf)
    return configDict

def changeIfaceMode(iface):
    os.system("sudo ifconfig " + iface + " down")
    mqttLog('System', 'Shuttinig down interface %s'%iface)
    os.system("sudo iwconfig " + iface + " mode monitor")
    mqttLog('System', 'Setting interface %s to monitore mode'%iface)
    os.system("sudo ifconfig " + iface + " up")
    mqttLog('System', 'Bringing up interface %s'%iface)

def sendData(pkts):
    url = 'https://' + gv.splunkServer + ':' + gv.splunkPort + gv.splunkURL
    authHeader = {'Authorization': 'Splunk %s' %gv.splunkToken}
    req = requests.post(url, headers=authHeader, json=pkts, verify=False)
    mqttLog('Sending data to Splunk server: %s' %req)

def createWlanList(wlan):
    wlans = readConfig(gv.wlansFile)
    frequencies = readConfig('config/frequencies.json')
    ssid = wlan['ssid']
    bssid = wlan['bssid']
    #channel = frequencies['fre2cha'][wlan['channel']]
    channel = [wlan['channel']]
    #rssi = wlan['rssi']
    wlanValue = {'bssid':bssid, 'channel':channel}
    #wlanValue = {'bssid':bssid, 'channel':channel, 'rssi':rssi}
    addValue = True
    
    # Append values if SSID exists (no duplicates)
    if ssid in wlans.keys():
        for a in wlans[ssid]:
            if a['bssid'] == bssid:
                addValue = False
        if addValue == True:
            wlans[ssid].append(wlanValue)

    # Add new SSID
    else:
        valueList = []
        valueList.append(wlanValue)
        wlans[ssid] = valueList

    writeWlanList(gv.wlansFile, wlans)

def readWlanList():
    with open(wlansFile, 'r') as wf:
        wlans = json.loads(wf)
    wf.close()
    return wlans

def writeWlanList(wlansFile, wlans):
    f = open(wlansFile, 'w')
    f.write(json.dumps(wlans, indent=4))
    f.close()
    mqttLog('Writing WLANs to %s' %wlansFile)
    #mqttLog('Writing WLANs to %s'%wlansFile)

