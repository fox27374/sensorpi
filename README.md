# sensorpi
## Raspberry Pi WLAN sensor

Use a RaspberryPi as a WLAN sensor and send 802.11 frame information in a structured JSON format to a Splunk server.

### scan.py
Scans the air on channels specified in config.json. The scantime is also set in this file. After the scan is complete, a JSON file is created that lists all wlans and the associated BSSIDs. This file is later used as a database for the continouse sniffing

### config.json
The main configuration file for the SensorPi and the connection to Splunk. The repository contains a template file **config-template.json** which has to be renamed and adapted to your needs.

### frametypes.json
This file contains the translations for the different frame types and subtypes. It is loaded during startup. The filename can be configured in the config.json file. Frametypes and description is copied form [Wikipedia - 802.11 Frame Types](https://en.wikipedia.org/wiki/802.11_Frame_Types)
