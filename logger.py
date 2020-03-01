#!/usr/bin/env python

import globalVars as gv
import paho.mqtt.client as mqtt
import logging
# set up logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename=gv.logFile,
                    filemode='a')

def on_connect(client, userdata, flags, rc):
    #print("Connected with result code " + str(rc))

    client.subscribe('sensorpi/log')

def on_message(client, userdata, msg):
    logging.info(str(msg.payload))
    #print(msg.topic + " " + str(msg.payload))

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect(gv.mqttServer, int(gv.mqttPort), 60)

try:
    client.loop_forever()
except:
    client.disconnect()

