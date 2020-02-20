#!/usr/bin/python

import os
import subprocess

pipPkg = ['scapy', 'requests']
dirs = ['log']

def installPipPkg(package):
    procInstall = subprocess.Popen(['pip', 'install', package], stderr=subprocess.PIPE)
    procInstallPipe = procInstall.communicate()
    if '--upgrade' in str(procInstallPipe):
        print('Upgrading PIP to the latest version')
        procUpgrade = subprocess.Popen(['pip', 'install', '--upgrade', 'pip'])

def checkPipPkg(pkg):
    procList = subprocess.Popen(['pip', 'freeze'], stdout=subprocess.PIPE)
    procGrep = subprocess.Popen(['grep', pkg], stdin=procList.stdout, stdout=subprocess.PIPE)
    procList.stdout.close()
    procGrepPipe = procGrep.communicate()[0]
    if procGrepPipe:
        return True
    else:
        return False


print('Checking / Installing required packages')
for pkg in pipPkg:
    if not checkPipPkg(pkg):
        print('Installing package %s' %pkg)
        installPipPkg(pkgi)
    else:
        print('Package %s installed already' %pkg)

print('Creating directories')
for directory in dirs:
    os.system('mkdir ' + directory)

print('Renaming config template file')
os.system('mv config/config-template.json config/config.json')

print('Creating empty wlans.json file')
os.system('echo "{}" > wlans.json')
