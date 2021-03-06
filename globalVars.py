#!/usr/bin/env python

import json

# Variables to share beween modules

def readConfig(configFile):
    with open(configFile, 'r') as cf:
        configDict = json.load(cf)
    return configDict

# Global variables
pkts = []
scanWLANBSSIDs = []
scanWLANChannels = []

# Load Configuration
configFile = 'config/config.json'
frameTypesFile = 'config/frametypes.json'

sensorPiConfig = readConfig(configFile)
frameTypes = readConfig(frameTypesFile)

# SensorPi
iface = sensorPiConfig['SensorPi']['Interface']
channels = sensorPiConfig['SensorPi']['Channels']
scanTime = sensorPiConfig['SensorPi']['Scantime']
rssiThreshold = sensorPiConfig['SensorPi']['rssiThreshold']
channelTime = sensorPiConfig['SensorPi']['Channeltime']
wlansFile = sensorPiConfig['SensorPi']['wlansFile']
frameTypesFile = sensorPiConfig['SensorPi']['frameTypesFile']
logFile = sensorPiConfig['SensorPi']['logFile']

# MQTT
mqttServer = sensorPiConfig['MQTT']['mqttServer']
mqttPort = sensorPiConfig['MQTT']['mqttPort']

# Splunk
splunkServer = sensorPiConfig['Splunk']['Server']
splunkPort = sensorPiConfig['Splunk']['Port']
splunkURL = sensorPiConfig['Splunk']['URL']
splunkToken = sensorPiConfig['Splunk']['Token']
splunkBulk = sensorPiConfig['Splunk']['Bulk']

