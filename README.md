# sensorpi
##Raspberry Pi WLAN sensor

Use a RaspberryPi as a WLAN sensor and send 802.11 frame information in a structured JSON format to a Splunk server.

###scan.py
Scans the air on channels specified in config.json. The scantime is also set in this file.
After the scan is complete, a JSON file is created that lists all wlans and the associated BSSIDs
This file is later used as a database for the continouse sniffing
