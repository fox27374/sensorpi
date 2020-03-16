#!/usr/bin/env python

import paho.mqtt.client as mqtt
import globalVars as gv
from splib import createWlanList
from json import loads

def on_connect(client, userdata, flags, rc):
    """Subscripe to MQTT topic"""
    client.subscribe('sensorpi/sensordata')

def on_message(client, userdata, msg):
    """Filter based on SSID and write data to file"""
    data = loads(msg.payload)
    createWlanList(data)

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect(gv.mqttServer, int(gv.mqttPort), 60)

try:
    client.loop_forever()
except:
    client.disconnect()
