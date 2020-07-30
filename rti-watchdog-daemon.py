#!/usr/bin/python3
# -*- coding: utf-8 -*-
# v1.0 Alexander Popov <popov.ap@gmail.com>. Initial release
# v1.1 added HTTP power reset option
from pandas import DataFrame
import pandas as pd
import socket   #for sockets
from datetime import datetime
import subprocess
import logging
import logging.handlers
import sys, os, time, atexit, signal
from signal import SIGTERM

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
filehandler = logging.handlers.TimedRotatingFileHandler('/var/log/rti-watchdog/daemon.log',when='midnight',interval=1,backupCount=10)
filehandler.setFormatter(logging.Formatter(fmt='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(filehandler)

"""
Status overview:
   * Init - ready to process. The RTI has not asked yet
   * Alive - The correct answer was received. The RTI is considered to be alive
State transition: Init -> Alive (next check in 'waitactive' seconds)
   * Fail - Message was send but RTI was not answered for it.
   * PwrReset - Power reset command was send to the RTI power outlet
State transition: Fail -> (check in 'waitfail' seconds again) -> PwrReset
   * Service - RTI is under service now. Skip it for processing. 

If RTI answer with incorrect string or answer received from incorrect address, it is placed to the Service state.
If RTI do not respond after power reset, it also placed to the Service state.
"""
allhosts = DataFrame([{'RTI': '192.168.21.12',  'NetPingAddr': '192.168.21.30',  'NetPingPwrOut': 1, 'NetPingScheme': 'snmp', 'Status': 'Init', 'LastTime': 'never', 'NextCheck': 'now', 'Uptime': '0 days'},
                      {'RTI': '192.168.22.12',  'NetPingAddr': '192.168.22.30',  'NetPingPwrOut': 1, 'NetPingScheme': 'snmp', 'Status': 'Init', 'LastTime': 'never', 'NextCheck': 'now', 'Uptime': '0 days'},
                      {'RTI': '192.168.23.12',  'NetPingAddr': '192.168.23.30',  'NetPingPwrOut': 1, 'NetPingScheme': 'snmp', 'Status': 'Init', 'LastTime': 'never', 'NextCheck': 'now', 'Uptime': '0 days'},
                      {'RTI': '192.168.24.12',  'NetPingAddr': '192.168.24.30',  'NetPingPwrOut': 1, 'NetPingScheme': 'snmp', 'Status': 'Init', 'LastTime': 'never', 'NextCheck': 'now', 'Uptime': '0 days'},
                      {'RTI': '192.168.25.12',  'NetPingAddr': '192.168.25.30',  'NetPingPwrOut': 1, 'NetPingScheme': 'snmp', 'Status': 'Init', 'LastTime': 'never', 'NextCheck': 'now', 'Uptime': '0 days'},
                      {'RTI': '192.168.26.12',  'NetPingAddr': '192.168.26.30',  'NetPingPwrOut': 1, 'NetPingScheme': 'snmp', 'Status': 'Init', 'LastTime': 'never', 'NextCheck': 'now', 'Uptime': '0 days'},
                      {'RTI': '192.168.27.12',  'NetPingAddr': '192.168.27.30',  'NetPingPwrOut': 1, 'NetPingScheme': 'snmp', 'Status': 'Init', 'LastTime': 'never', 'NextCheck': 'now', 'Uptime': '0 days'},
                      {'RTI': '192.168.27.112', 'NetPingAddr': '192.168.27.130', 'NetPingPwrOut': 1, 'NetPingScheme': 'snmp', 'Status': 'Init', 'LastTime': 'never', 'NextCheck': 'now', 'Uptime': '0 days'},
                      {'RTI': '192.168.27.212', 'NetPingAddr': '192.168.27.230', 'NetPingPwrOut': 1, 'NetPingScheme': 'snmp', 'Status': 'Init', 'LastTime': 'never', 'NextCheck': 'now', 'Uptime': '0 days'},
                      {'RTI': '192.168.30.12',  'NetPingAddr': '192.168.30.30',  'NetPingPwrOut': 1, 'NetPingScheme': 'snmp', 'Status': 'Init', 'LastTime': 'never', 'NextCheck': 'now', 'Uptime': '0 days'},
                  ])
allhosts = allhosts.set_index(['RTI'])

# host from where we sending request
port = 4999
lochost='192.168.97.12'
msg = "12345"
timeout = 5
waitanswer = 5

# we suppose that system sendmail configured somehow to send these emails by means of unix mail program. In our case we use ssmtp.
recipient = "support@example.com"
carboncopy="engineer@example.com"
subject = "RTI watchdog ALARM"
sender = "From: RTI WATCHDOG <rti_watchdog@example.com>"

waitactive = 900 # seconds 900
waitfail = 1800 # seconds 180
waitpwrreset = 600 # seconds
waitservice = 86400 # seconds 86400

class Daemon(object):
    """
    Subclass Daemon class and override the run() method.
    """
    def __init__(self, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile
 
    def daemonize(self):
        """
        Deamonize, do double-fork magic.
        """
        try:
            pid = os.fork()
            if pid > 0:
                # Exit first parent.
                sys.exit(0)
        except OSError as e:
            message = "Fork #1 failed: {}\n".format(e)
            sys.stderr.write(message)
            sys.exit(1)
 
        # Decouple from parent environment.
        os.chdir("/")
        os.setsid()
        os.umask(0)
 
        # Do second fork.
        try:
            pid = os.fork()
            if pid > 0:
                # Exit from second parent.
                sys.exit(0)
        except OSError as e:
            message = "Fork #2 failed: {}\n".format(e)
            sys.stderr.write(message)
            sys.exit(1)
 
        logger.info('deamon going to background, PID: {}'.format(os.getpid()))
 
        # Redirect standard file descriptors.
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(self.stdin, 'r')
        so = open(self.stdout, 'a+')
        se = open(self.stderr, 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
 
        # Write pidfile.
        pid = str(os.getpid())
        open(self.pidfile,'w+').write("{}\n".format(pid))
 
        # Register a function to clean up.
        atexit.register(self.delpid)
 
    def delpid(self):
        os.remove(self.pidfile)
 
    def start(self):
        """
        Start daemon.
        """
        # Check pidfile to see if the daemon already runs.
        try:
            pf = open(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None
 
        if pid:
            message = "Pidfile {} already exist. Daemon already running?\n".format(self.pidfile)
            sys.stderr.write(message)
            sys.exit(1)
 
        # Start daemon.
        self.daemonize()
        self.run()
 
    def status(self):
        """
        Get status of daemon.
        """
        try:
            pf = open(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            message = "There is not PID file. Daemon already running?\n"
            sys.stderr.write(message)
            sys.exit(1)
 
        try:
            procfile = open("/proc/{}/status".format(pid), 'r')
            procfile.close()
            message = "There is a process with the PID {}\n".format(pid)
            sys.stdout.write(message)
        except IOError:
            message = "There is not a process with the PID {}\n".format(self.pidfile)
            sys.stdout.write(message)
 
    def stop(self):
        """
        Stop the daemon.
        """
        # Get the pid from pidfile.
        try:
            pf = open(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError as e:
            message = str(e) + "\nDaemon not running?\n"
            sys.stderr.write(message)
            sys.exit(1)
 
        # Try killing daemon process.
        try:
            os.kill(pid, SIGTERM)
            time.sleep(1)
        except OSError as e:
            print(str(e))
            sys.exit(1)
 
        try:
            if os.path.exists(self.pidfile):
                os.remove(self.pidfile)
        except IOError as e:
            message = str(e) + "\nCan not remove pid file {}".format(self.pidfile)
            sys.stderr.write(message)
            sys.exit(1)
 
    def restart(self):
        """
        Restart daemon.
        """
        self.stop()
        time.sleep(1)
        self.start()
 
    def run(self):
        """
        You should override this method when you subclass Daemon.
        It will be called after the process has been daemonized by start() or restart().
 
        Example:
 
        class MyDaemon(Daemon):
            def run(self):
                while True:
                    time.sleep(1)
        """
        
class MyDaemon(Daemon):
    def run(self):
        # create UDP socket for sending
        try:
            sending = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error:
            logger.info('Failed to create socket for sending')
            sys.exit()
        # create UDP socket for receiving
        try:
            receiving = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error:
            logger.info('Failed to create socket for receiving')
            sys.exit()

        receiving.bind((lochost, port))
        receiving.settimeout(waitanswer)

        # send string and receiving answer for the given RTI
        def sendrecudp(rti, port=port, msg=msg):
            logger.debug("sendrecudp: Processed RTI is {}".format(rti))
            try:
                sending.sendto(msg.encode(), (rti, port))
            except(socket.error, msg):
                logger.info("Error Code : {} Message {}".format(str(msg[0]), msg[1]))
            try:
                data = 'None'
                data, addr = receiving.recvfrom(4096)
                if data.decode() == "67890" and addr[0] == rti:
                    logger.debug("Received message: {} From: {}".format(data.decode(),addr[0]))
                    return "Received"
                else:
                    logger.debug("Unexpected answer: {} From: {}".format(data.decode(),addr[0]))
                    return "Unexpected"
            except(socket.timeout):
                logger.debug("Host {}: Receiving timeout expired".format(rti))
                return "Timeout"

        def resetpower(rti):
            if allhosts.ix[rti, 'NetPingScheme'] == 'snmp':
                snmpcommand = "/usr/bin/snmpset -v 2c -c SWITCH %s .1.3.6.1.4.1.25728.5800.3.1.2.%s i 1" % (allhosts.ix[rti, 'NetPingAddr'], allhosts.ix[rti, 'NetPingPwrOut'],)            
                logger.debug("resetpower: Executing: {}\n".format(snmpcommand))
                process = subprocess.Popen(snmpcommand.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = process.communicate()
                logger.debug("resetpower: SNMP STDERR: {}\n".format(error.decode()))
                logger.info("resetpower: SNMP NetPing return: {}\n".format(output.decode()))
                return output.decode()
            elif allhosts.ix[rti, 'NetPingScheme'] == 'http':
                wgetcmd = "/usr/bin/wget --user visor --password ping -O - -- http://%s/relay.cgi?r%s=f,10" % (allhosts.ix[rti, 'NetPingAddr'], allhosts.ix[rti, 'NetPingPwrOut'],)
                process = subprocess.Popen(wgetcmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                output, error = process.communicate()
                logger.debug("resetpower: HTTP STDERR: {}\n".format(error.decode()))
                logger.info("resetpower: HTTP NetPing return: {}\n".format(output.decode()))
                return output.decode()
            else:
                logger.info("resetpower: Unsupported NetPing Scheme: {}\n".format(allhosts.ix[rti, 'NetPingScheme']))
                #sys.exit()

        def sendemail(body, recipient=recipient, carboncopy=carboncopy, subject=subject, sender=sender):
            process = subprocess.Popen(['mail', '-a', sender, '-s', subject, recipient, '-c', carboncopy],
                                       stdin=subprocess.PIPE)
            logger.debug("sendemail: Sending email:\nTo: {}\nCC:{}\nBody:\n{}\n".format(recipient,carboncopy,body.decode()))
            process.communicate(body)

        while True:
            time.sleep(1)
            for rti in allhosts.index:
                time.sleep(1)
                recstatus = ''
                ########### Working with current status and count time #######################
                if allhosts.ix[rti, 'Status'] == 'Service':
                    if allhosts.ix[rti, 'LastTime'] == 'never':
                        #logger.debug("Host {} was set to Service status in the configuration. We do not check it.".format(rti))
                        continue
                    # if Service status was set one day ago, move RTI to Init state.
                    elif (datetime.now() - datetime.strptime(allhosts.ix[rti, 'LastTime'], "%Y-%m-%d %H:%M:%S")).seconds >= waitservice:
                        logger.debug("Host {} was set to Service status and waitservce timer expired. It placed to the Init state.".format(rti))
                        allhosts.ix[rti, 'Status'] = 'Init'
                        body = "Moving RTI %s from status Service to Init.\nService status was set at %s" % (rti, allhosts.ix[rti, 'LastTime'])
                        sendemail(body.encode())
                    else:
                        continue
                # initial check
                elif allhosts.ix[rti, 'Status'] == 'Init':
                    logger.debug("Host {} in the Init state, checking...".format(rti))
                    recstatus = sendrecudp(rti)
                # if host is alive next check will be in 'waitactive' seconds
                elif (allhosts.ix[rti, 'Status'] == 'Alive' and
                    (datetime.now() - datetime.strptime(allhosts.ix[rti, 'LastTime'], "%Y-%m-%d %H:%M:%S")).seconds >= waitactive):
                    logger.debug("Host {} waitactive exired, checking...".format(rti))
                    recstatus = sendrecudp(rti)
                # if host is fail next check will be in 'waitfail' seconds 
                elif (allhosts.ix[rti, 'Status'] == 'Fail' and 
                (datetime.now() - datetime.strptime(allhosts.ix[rti, 'LastTime'], "%Y-%m-%d %H:%M:%S")).seconds >= waitfail):
                    logger.debug("Host {} was Fail, the second check attempt".format(rti))
                    recstatus = sendrecudp(rti)
                # if host was reseted next check will be in 'waitpwrreset' seconds 
                elif (allhosts.ix[rti, 'Status'] == 'PwrReset' and 
                (datetime.now() - datetime.strptime(allhosts.ix[rti, 'LastTime'], "%Y-%m-%d %H:%M:%S")).seconds >= waitpwrreset):
                    logger.debug("Host {} was PwrReset, and time for it boot expired, checking".format(rti))
                    recstatus = sendrecudp(rti)
                else:
                    pass
                # Working with received status ######################################
                if recstatus == "Received":
                    allhosts.ix[rti, 'LastTime'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    allhosts.ix[rti, 'Status'] = 'Alive'
                    logger.debug("Host {} status Alive".format(rti))
                elif recstatus == "Timeout":
                    # if host already was fail and we have not received answer, reset power
                    if allhosts.ix[rti, 'Status'] == 'Fail':
                        allhosts.ix[rti, 'LastTime'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        allhosts.ix[rti, 'Status'] = 'PwrReset'
                        logger.info("Host {} does not reply to us two times. Resetting power".format(rti))
                        # reset power
                        resetresult = resetpower(rti)
                        if resetresult != '':
                            logger.debug("Host {}, resetpower return: {}\n".format(rti, resetresult))
                            reseterror = "Resetting power result: %s\n" % resetresult
                        # send email
                        logger.info("Host {} sending email alarm".format(rti))
                        body = "%s resetting power for RTI %s\nNetPing address: %s\n%s" % (allhosts.ix[rti, 'LastTime'], rti, allhosts.ix[rti, 'NetPingAddr'], reseterror)
                        sendemail(body.encode())
                        # if host was in PwrReset state and do not answer, place it to the service state
                    elif allhosts.ix[rti, 'Status'] == 'PwrReset':
                        allhosts.ix[rti, 'LastTime'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        allhosts.ix[rti, 'Status'] = 'Service'
                        logger.info("Host {} was reseted and do not answer to us. Placing it to the service state".format(rti))
                        # sending alarm
                        body = "%s RTI %s does not respond after power reset.\nIt is placed to the Service state and is not checked." % (allhosts.ix[rti, 'LastTime'], rti)
                        sendemail(body.encode())
                    else:
                        allhosts.ix[rti, 'LastTime'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        allhosts.ix[rti, 'Status'] = 'Fail'
                        logger.info("Host {} do not reply to us. Placing it to the fail state".format(rti))
                elif recstatus == "Unexpected":
                    logger.info("Host {} answered to as with unexpected string or address, place it to the service state".format(rti))
                    allhosts.ix[rti, 'Status'] = 'Service'
                    # sending alarm
                    body = "%s RTI %s respond with wrong answer string to our requests or reply was send from wrong address.\nIt placed to the Service state and is not checked." % (allhosts.ix[rti, 'LastTime'], rti)
                    sendemail(body.encode())
                else:
                    pass
                    #logger.debug('Nothing do, wait for timers...')

if __name__ == "__main__":
    daemon = MyDaemon('/var/run/rti-watchdog/rti-watchdog-daemon.pid')
    if len(sys.argv) == 2:
        logger.info('{} {}'.format(sys.argv[0],sys.argv[1]))
 
        if 'start' == sys.argv[1]:
            daemon.start()
        elif 'stop' == sys.argv[1]:
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            daemon.restart()
        elif 'status' == sys.argv[1]:
            daemon.status()
        else:
            print ("Unknown command")
            sys.exit(2)
        sys.exit(0)
    else:
        logger.warning('show cmd deamon usage')
        print ("Usage: {} start|stop|restart".format(sys.argv[0]))
        sys.exit(2)
