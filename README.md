# rti-watchdog
The aim of this project was to monitor a group of RTI XP-3 control processors by sending them some text string and expecting same string back.

I observed that if the XP-3 is hung for some reason it can answer  ICMP ping but does not reply to that UDP request.

If the XP-3 has not replied for some time I ask managed power outlet to bounce the power for it. The daemon sending emails in some cases.

All configurtion, addresses of XP-3, addresses of power outlets (NetPing here) workng states and monitoring data stored in memory pandas dataframe and I do not need it persist between daemon restart. Currently I don't need this data to be acquired by others application and monitoring systems.
Daemon writes the log file and it might be useful for track events and actions.

Related files:
* ```/usr/local/sbin/rti-watchdog-daemon.py``` - the daemon itself
* ```/var/run/rti-watchdog/rti-watchdog-daemon.pid``` - PID file created by systemd
* ```/etc/systemd/system/rti-watchdog.service``` - systemd service for automatic startup of the daemon
* ```/var/log/rti-watchdog/``` - folder where the daemon keeps its logs, has owners 'nobody:nogroup' in my case. Log rotation is done by python logger module and daemon itself, not system logrotate.
