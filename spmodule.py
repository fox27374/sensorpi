#!/usr/bin/python

import json
import os
import time
import requests
from scapy.all import *

def readConfig(configFile):
    with open(configFile, 'r') as cf:
        configDict = json.load(cf)
    return configDict

def changeIfaceMode(iface):
    os.system("ifconfig " + iface + " down")
    os.system("iwconfig " + iface + " mode monitor")
    os.system("ifconfig " + iface + " up")

def sendData(pkts, splunkServer, splunkPort, splunkURL, splunkToken):
    url = 'https://' + splunkServer + ':' + splunkPort + splunkURL
    authHeader = {'Authorization': 'Splunk %s'%splunkToken}
    req = requests.post(url, headers=authHeader, json=pkts, verify=False)
    print(req)

def createWlanList(wlan, wlans):
    ssid = wlan['ssid']
    bssid = wlan['bssid']
    wlanValue = {'bssid':bssid, 'channel':wlan['channel']}
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

def writeWlanList(wlansFile, wlans):
    f = open(wlansFile, 'w')
    f.write(json.dumps(wlans, indent=4))
    f.close()


### HTTP Server section

def createConfigTable(config):
    return 0
