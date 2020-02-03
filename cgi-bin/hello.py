#!/usr/bin/python

import json
import sys
sys.path.append('/home/dk/sensorpi/')
from spmodule import *

def loadHeader():
    print("Content-Type: text/html\n")
    print("<!doctype html><title>SensorPi Control</title><h2>SensorPi Control</h2>")

# Read config file and add data to form
def loadForm(sensorPiConfig):
    print('<form action="/action_page.php">')
    print('<fieldset>')
    print('<legend>SensorPi Configuration</legend>')
    print('<table>')
    for key in sensorPiConfig['SensorPi'].keys():
        value = sensorPiConfig['SensorPi'][key]
        print('<tr><td width="120">%s</td>'%key)
        print('<td><input type="text" name="%s" value=%s></td></tr>'%(key, value))
    print('</table>')
    print('</fieldset>')
    print('<br>')
    print('<fieldset>')
    print('<legend>Splunk Configuration</legend>')
    print('<table>')
    for key in sensorPiConfig['Splunk'].keys():
        value = sensorPiConfig['Splunk'][key]
        print('<tr><td width="120">%s</td>'%key)
        print('<td><input type="text" name="%s" value=%s></td></tr>'%(key, value))
    print('</table>')
    print('</fieldset>')
    print('</form>')

def loadWLANList(wlans):
    print('<h3>WLANs</h3>')
    print('<select name="WLANs">')
    for wlan in wlans.keys():
        print('<option value="%s">%s</option>'%(wlan, wlan))
    print('</select>')


configFile = 'config.json'
sensorPiConfig = readConfig(configFile)
wlans = readConfig(sensorPiConfig['SensorPi']['wlansFile'])
loadHeader()
loadWLANList(wlans)
print('<br>')
loadForm(sensorPiConfig)
