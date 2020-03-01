#!/usr/bin/env python

import globalVars as gv
from splib import sendData
import paho.mqtt.client as mqtt
import json


def on_connect(client, userdata, flags, rc):
    client.subscribe("sensorpi/sensordata")

def on_message(client, userdata, msg):
    global bulk
    data = json.loads(msg.payload)
    if len(bulk) <= int(gv.splunkBulk):
        bulk.append(data)
    else:
        sendData(bulk)
        bulk = []
        bulk.append(data)

bulk = []
client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect(gv.mqttServer, int(gv.mqttPort), 60)

try:
    client.loop_forever()
except:
    client.disconnect()

