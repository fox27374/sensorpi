#!/usr/bin/env python

import json
import os
import time
import requests
import globalVars as gv
from scapy.all import *
import logging

# set up logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename=gv.logFile,
                    filemode='a')
logging.getLogger("urllib3").setLevel(logging.WARNING)

def beacon(pkt):
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info
        bssid = pkt[Dot11].addr3
        #channel = int(ord(pkt[Dot11Elt:3].info))
        channel = pkt[RadioTap].Channel
        #try:
        #    extra = pkt[RadioTap].notdecoded
        #    rssi = -(256-ord(extra[-4:-3]))
        #except:
        #    rssi = -100
        #wlan = {'ssid':ssid.decode('UTF-8'), 'bssid':bssid, 'channel':channel, 'rssi':rssi}
        wlan = {'ssid':ssid.decode('UTF-8'), 'bssid':bssid, 'channel':str(channel)}
        createWlanList(wlan)


def readConfig(configFile):
    with open(configFile, 'r') as cf:
        configDict = json.load(cf)
    return configDict

def changeIfaceMode(iface):
    os.system("ifconfig " + iface + " down")
    logging.info('Shutting down interface %s'%iface)
    os.system("iwconfig " + iface + " mode monitor")
    logging.info('Setting interface %s to monitore mode'%iface)
    os.system("ifconfig " + iface + " up")
    logging.info('Bringing up interface %s'%iface)

def sendData(pkts, splunkServer, splunkPort, splunkURL, splunkToken):
    url = 'https://' + splunkServer + ':' + splunkPort + splunkURL
    authHeader = {'Authorization': 'Splunk %s'%splunkToken}
    logging.info('Sending data to Splunk server')
    req = requests.post(url, headers=authHeader, json=pkts, verify=False)
    logging.info('Reply: %s'%req)

def createWlanList(wlan):
    wlans = readConfig(gv.wlansFile)
    frequencies = readConfig('config/frequencies.json')
    ssid = wlan['ssid']
    bssid = wlan['bssid']
    channel = frequencies['fre2cha'][wlan['channel']]
    #rssi = wlan['rssi']
    #wlanValue = {'bssid':bssid, 'channel':wlan['channel'], 'rssi':rssi}
    wlanValue = {'bssid':bssid, 'channel':channel}
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
    logging.info('Writing WLANs to %s'%wlansFile)

