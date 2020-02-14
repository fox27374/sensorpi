#!/usr/bin/env python

# Variables to share beween modules

from spmodule import readConfig

# Global variables
pkts = []
scanWLANBSSIDs = []

# Load Configuration
configFile = 'config.json'
frameTypesFile = 'frametypes.json'

sensorPiConfig = readConfig(configFile)
frameTypes = readConfig(frameTypesFile)

# SensorPi
iface = sensorPiConfig['SensorPi']['Interface']
channels = sensorPiConfig['SensorPi']['Channels']
scanTime = sensorPiConfig['SensorPi']['Scantime']
channelTime = sensorPiConfig['SensorPi']['Channeltime']
wlansFile = sensorPiConfig['SensorPi']['wlansFile']
frameTypesFile = sensorPiConfig['SensorPi']['frameTypesFile']

# Splunk
splunkServer = sensorPiConfig['Splunk']['Server']
splunkPort = sensorPiConfig['Splunk']['Port']
splunkURL = sensorPiConfig['Splunk']['URL']
splunkToken = sensorPiConfig['Splunk']['Token']
splunkBulk = sensorPiConfig['Splunk']['Bulk']

