#!/usr/bin/env python

import json
import os
import time
import requests
from scapy.all import *
import logging

# set up logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='app.log',
                    filemode='w')
logging.getLogger("urllib3").setLevel(logging.WARNING)

# PKT Filter
def data(pkt):
    global frameTypes
    global scanWLANBSSIDs
    global pkts
    pktRetry = False
    pktToDS = False
    pktFromDS = False
    pktBSSID = pkt[Dot11].addr3
    # Get ToDS and FromDS flags if packet is of type data
    # and read BSSID from a different address field
    if pkt.type == 2:
        pktToDS = pkt.FCfield & 0x4 != 0
        pktFromDS = pkt.FCfield & 0x5 != 0
        if pktToDS: pktBSSID = pkt[Dot11].addr1
        if pktFromDS: pktBSSID = pkt[Dot11].addr2
    # Check if BSSID is in one of the addres fields
    # otherwise the frame is not interresting
    if pktBSSID in scanWLANBSSIDs:
        pktRetry = pkt[Dot11].FCfield.retry != 0
        pktType = frameTypes[str(pkt.type)]['Name']
        pktSubtype = frameTypes[str(pkt.type)][str(pkt.subtype)]
        pktTime = time.time() #Epoch time for Splunk HEC

        #pktChannel = int(ord(pkt[Dot11Elt:3].info))
        pktChannel = pkt[RadioTap].Channel
        if pktType == 0:
            pktSSID = pkt[Dot11Elt].info
            pktSSID = pktSSID.decode('UTF-8')
        else:
            pktSSID = 'NA'

        pktInfo = {"time":pktTime, "event":{"type":pktType, "subtype":pktSubtype, "tods":pktToDS, "fromds":pktFromDS, "ssid":pktSSID, "bssid":pktBSSID, "channel":pktChannel, "retry":pktRetry}}
        if len(pkts) <= int(splunkBulk):
            pkts.append(pktInfo)
        else:
            sendThread = threading.Thread(target=sendData, args=(pkts, splunkServer, splunkPort, splunkURL, splunkToken))
            sendThread.start()
            pkts = []
            pkts.append(pktInfo)


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
    wlans = readConfig('wlans.json')
    frequencies = readConfig('frequencies.json')
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

    writeWlanList('wlans.json', wlans)

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

