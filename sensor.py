#!/usr/bin/env python

import time
import requests
import globalVars as gv
from scapy.all import sniff
from splib import *
import urllib3

# Disable certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Read Channels and BSSIDs from file
# Filter by SSID that is passed from the main process
wlans = readConfig('wlans.json')
scanWLANSSID = str(sys.argv[1])
scanWLANChannels = []
scanWLANBSSIDs = []
for wlanInfo in wlans[scanWLANSSID]:
    scanWLANBSSIDs.append(wlanInfo['bssid'])
    scanWLANChannels.append(wlanInfo['channel'])

# Remove duplicates
scanWLANChannels = list(dict.fromkeys(scanWLANChannels))

# PKT Filter
def data(pkt):
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
    if pktBSSID in gv.scanWLANBSSIDs:
        pktRetry = pkt[Dot11].FCfield.retry != 0
        pktType = gv.frameTypes[str(pkt.type)]['Name']
        pktSubtype = gv.frameTypes[str(pkt.type)][str(pkt.subtype)]
        pktTime = time.time() #Epoch time for Splunk HEC

        #pktChannel = int(ord(pkt[Dot11Elt:3].info))
        pktChannel = pkt[RadioTap].Channel
        if pktType == 0:
            pktSSID = pkt[Dot11Elt].info
            pktSSID = pktSSID.decode('UTF-8')
        else:
            pktSSID = 'NA'

        pktInfo = {"time":pktTime, "event":{"type":pktType, "subtype":pktSubtype, "tods":pktToDS, "fromds":pktFromDS, "ssid":pktSSID, "bssid":pktBSSID, "channel":pktChannel, "retry":pktRetry}}
        if len(gv.pkts) <= int(gv.splunkBulk):
            gv.pkts.append(pktInfo)
        else:
            sendThread = threading.Thread(target=sendData, args=(gv.pkts, gv.splunkServer, gv.splunkPort, gv.splunkURL, gv.splunkToken))
            sendThread.start()
            gv.pkts = []
            gv.pkts.append(pktInfo)

# Logging some info
logging.info('Starting sensor for SSID: %s' %scanWLANSSID)
logging.info('Channels for this SSID: %s' %scanWLANChannels)
logging.info('BSSIDs for this SSID: %s' %scanWLANBSSIDs)
logging.info('Changing channel every %s seconds' %gv.channelTime)

# Start sniffing loop
while True:
    for scanWLANChannel in scanWLANChannels:
        logging.info('Setting interface to channel %s'%scanWLANChannel)
        os.system("iwconfig " + gv.iface + " channel " + str(scanWLANChannel))
        loopTime = time.time() + int(gv.channelTime)
        while time.time() < loopTime:
            sniff(iface=gv.iface, prn=data, count=10, timeout=3, store=0)
