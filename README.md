# ZabbixDomainMonitor


# Install
copy script to external scripts dir
create venv 
sudo python3 -m venv /usr/lib/zabbix/externalscripts/.dmvenv
chown zabbix.zabbix -R /usr/lib/zabbix/externalscripts/.dmvenv
/usr/lib/zabbix/externalscripts/.dmvenv/bin/pip3 install -r /opt/zDomainMonitor/requirements.txt
