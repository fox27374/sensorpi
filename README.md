![Overview](https://github.com/fox27374/sensorpi/blob/master/overview.png)

# SensorPi (still under development)
## Raspberry Pi WLAN sensor

Use a RaspberryPi as a WLAN sensor and send 802.11 frame information in a structured JSON format to a Splunk server.

## Requirements

### Hardware
* RaspberryPi in any version and OS that supports the mentioned software (tested with Arch) 
* WLAN adapter that can be set to promiscuous mode (currently tested with RTL8812AU)

### Software
* Python 3
* python-pip
* virtualenv
* MQTT (localhost)

### Installation
After the git clone do the following:
```
cd sensorpi
python -m venv env
source env/bin/activate
./setup.py
Modify the config.json file to your needs
```

## Files explained

### main.py
The main process that starts the different subprocesses.

### setup.py
The setup routine for initialising the environment. It installs pip modules and creates some folders and files

### scanner.py
Scans the air on channels specified in config.json. The scantime is also set in this file. After the scan is complete, a JSON file is created that lists all wlans and the associated BSSIDs. This file is later used as a database for the continouse sniffing

### sensor.py
Is started by the main process. The only parameter that the script needs is the SSID. Based on this, channels and BSSIDs are read from the wlans.json file created by the scanner.py script. It scans the air, extracts information from pakets and creates a JSON structure that is then send to the MQTT broker in the sensorpi/sensordata topic.

### forwarder.py
Listens to the MQTT topic sensorpi/sensordata and sends the data to the Splunk server via the HEC (HTTP Event Collector)

### logger.py
Listens to the MQTT topic sensorpi/log and writes the data to a logfile

### splib.py
A library file with a some routines that are used by the other scripts

### config.json
The main configuration file for the SensorPi and the connection to Splunk. The repository contains a template file **config-template.json** which has to be renamed and adapted to your needs.

### frametypes.json
This file contains the translations for the different frame types and subtypes. It is loaded during startup. The filename can be configured in the config.json file. Frametypes and description is copied form [Wikipedia - 802.11 Frame Types](https://en.wikipedia.org/wiki/802.11_Frame_Types)

### frequencies.json
A frequency conversation file ti channels and the other way round

## ToDo
* Create webgui for configuration (maybe flask)
* Create clean overview of the running processes and the option to kill / restart them
* Start subprocesses from the main process in a nice and tidy way
* Implement error handling
* Improve performance (maybe threading)

