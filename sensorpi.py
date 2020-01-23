#!/usr/bin/python


import os
import time
import json
from scapy.all import *

# Configuration
scanTime = 10
channels = (1, 6, 11)

# Variables
wlans = {}

if len(sys.argv) ==  2:
    iface = str(sys.argv[1])
else:
    iface = "wlan0"

os.system("ifconfig " + iface + " down") 
os.system("iwconfig " + iface + " mode monitor")
os.system("ifconfig " + iface + " up")

def beacon(pkt):
    if pkt.haslayer(Dot11Beacon):
        ap = pkt.addr2
        ssid = pkt[Dot11Elt].info
        bssid = pkt[Dot11].addr3    
        channel = int(ord(pkt[Dot11Elt:3].info))
        wlan = {'SSID':ssid.decode('UTF-8'), 'AP':ap, 'BSSID':bssid, 'CHANNEL':channel}
        createWlanList(wlan)

def createWlanList(wlan):
    ssid = wlan['SSID']
    ap = wlan['AP']
    channel = wlan['CHANNEL']
    wlanValue = {'AP':ap, 'CHANNEL':channel}
    addValue = True
    
    # Append values if SSID exists (no duplicates)
    if ssid in wlans.keys():
        for a in wlans[ssid]:
            if a['AP'] == ap:
                addValue = False
        if addValue == True:
            wlans[ssid].append(wlanValue)

    # Create new SSID
    else:
        valueList = []
        valueList.append(wlanValue)
        wlans[ssid] = valueList


print('Scanning for %s seconds to get all WLANs on channels %s'%(scanTime, channels))
loopTime = time.time() + scanTime
while time.time() < loopTime:
    for channel in channels:
        os.system("iwconfig " + iface + " channel " + str(channel))
        sniff(iface=iface, prn=beacon, count=10, timeout=3, store=0)

print(json.dumps(wlans, indent=4))
