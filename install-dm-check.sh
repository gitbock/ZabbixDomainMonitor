#!/bin/bash

PATH=$PATH:/bin:/usr/bin
export PATH

# Zabbix Server Config File to extract script directory
ZABBIX_SERVER_CONF="/etc/zabbix/zabbix_server.conf"

# Path to install script to. extracted from zabbix config
INSTALL_PATH=""

## Check prerequisits - python
function check_prerequisits () {
    PYTHON3_INSTALLED=`type -P python3`
    if [[ ! $PYTHON3_INSTALLED =~ 'python3' ]];
    then
        echo "Python 3 is not installed. This is a requirement. Please install by "
        echo " sudo yum install python3 (for redhat)"
        echo " sudo apt install python3 (for ubuntu)"
        exit -1
    fi

    PIP3_INSTALLED=`python3 -m pip --version`
    if [[ $PIP3_INSTALLED =~ 'No module' ]];
    then
        echo "Python3 PIP is not installed. This is a requirement. Please install by "
        echo " sudo yum install python3-pip (for redhat)"
        echo " sudo apt install python3-pip (for ubuntu)"
        exit -1
    fi

}

function install_dm_venv () {
    echo "Install to $INSTALL_PATH"

}

check_prerequisits
$INSTALL_PATH=`cat $ZABBIX_SERVER_CONF`
# | grep ExternalScripts=`
# | sed -E "s/^.*=(.*)$/\1/"`


install_dm_venv




exit 0
