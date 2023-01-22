# ZabbixDomainMonitor


# Install
copy script to external scripts dir
create venv 
sudo python3 -m venv /usr/lib/zabbix/externalscripts/.dmvenv
chown zabbix.zabbix -R /usr/lib/zabbix/externalscripts/.dmvenv
/usr/lib/zabbix/externalscripts/.dmvenv/bin/pip3 install -r /opt/zDomainMonitor/requirements.txt


# Agent

prereq
- python3
- venv


sudo mkdir -p /etc/zabbix/scripts/dm
sudo python3 -m venv /etc/zabbix/scripts/dm/.dmvenv
