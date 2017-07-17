#!/usr/bin/env python2
"""
This is a quick python script allowing regular expressions to be defined to
process generic UDP messages (e.g. UDP syslog) for usernames, ip, and mac
addresses.

The script assumes mac addresses will be included in all messages and when a
full user<->mac<->ip address mapping is formed will sent a User-ID update to the
configured palo alto firewall

Author: Mitchell Hewes <me@mitcdh.com>

Requires:
    peewee
    pandevice
"""
import logging
import SocketServer
import re
import os
import time
import Queue

from datetime import datetime
from threading import Thread

from peewee import *
from playhouse.sqliteq import SqliteQueueDatabase
from pandevice.base import PanDevice

# Variables to take from os environment
LISTEN_HOST = os.environ.get('LISTEN_HOST','0.0.0.0')
LISTEN_PORT = int(os.environ.get('LISTEN_PORT','1514'))
LOCAL_DOMAIN = os.environ.get('LOCAL_DOMAIN','')
DB_PATH = os.environ.get('DB_PATH','device.db')
TIMEOUT = os.environ.get('TIMEOUT','5')

# logging configuration
logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=os.environ.get("LOG_LEVEL", "INFO"))

# palo alto connection must be defined
try:
    PA_HOSTNAME = os.environ['PA_HOSTNAME']
    PA_USERNAME = os.environ['PA_USERNAME']
    PA_PASSWORD = os.environ['PA_PASSWORD']
except KeyError as e:
    logging.error( "CONFIG: required environment config variable %s is undefined" % (e))
    raise
else:
    logging.debug( "CONFIG: All PA_ environment variables defined")


# import our loggers and their associated regex from logger_definitions.py
try:
    from logger_definitions import LOGGER_DEFINITIONS
except ImportError as e:
    logging.error( "CONFIG: failed to import LOGGER_DEFINITIONS from 'logger_definitions.py'")
    raise
else:
    logging.debug( "CONFIG: imported LOGGER_DEFINITIONS from 'logger_definitions.py'")

# create our database in meta
# (can't defer as OperationalError exceptions are raised in thread)
try:
    DB = SqliteQueueDatabase(DB_PATH)
except:
    logging.error( "DB: failed to create SqliteQueueDatabase instance for path %s" % (DB_PATH) )
    raise
else:
    logging.debug( "DB: successfully created SqliteQueueDatabase instance at path %s" % (DB_PATH) )

# Create a queue to store ip/user pairs
UIDQ = Queue.Queue(maxsize=0)

# PeeWee Object Definition
class Device(Model):
    mac = CharField(unique=True)
    user = CharField(default="")
    ip = CharField(default="")
    timestamp = DateTimeField(default=datetime.now())

    class Meta:
        database = DB

class PA_UID_Update_Worker(Thread):
    def __init__(self, pafw, q, timeout):
        super(PA_UID_Update_Worker, self).__init__()
        self.pafw = pafw
        self.q = q
        self.timeout = timeout
        self.current_timeout = timeout

    def run(self):
        while True:
            try:
                user, ip = self.q.get(block=True, timeout=15)
                try:
                    self.pafw.userid.login(user, ip)
                except PanURLError as e:
                    logging.error( "PAN: host %s temporarily failed update with exception (%s) pausing worker for %ss queue size %s" % (PA_HOSTNAME, ip, user, e, self.timeout, self.q.qsize()))
                    self.q.put((user, ip))
                    self.q.task_done()
                    time.sleep(self.current_timeout)
                    self.current_timeout = self.current_timeout * 2
                except Exception as e:
                    logging.error( "PAN: host %s permanently failed update for map ip %s --> user %s (%s) removed from queue" % (PA_HOSTNAME, ip, user, e))
                    self.q.task_done()
                else:
                    logging.info( "PAN: host %s updated with map ip %s --> user %s" % (PA_HOSTNAME, ip, user))
                    self.q.task_done()
                    self.current_timeout = self.timeout
            except Queue.Empty:
                pass

# Customised so we can ignore from hosts we haven't defined a pattern for
class PA_UID_UDP_Server(SocketServer.ThreadingUDPServer):
    def verify_request(self, request, client_address):
        if client_address[0] in LOGGER_DEFINITIONS:
            return True
        else:
            logging.debug("MSG: received message from %s with no associated logger definition" % (client_address[0]) )
            return False


class PA_UID_UDP_Handler(SocketServer.BaseRequestHandler):
    # return a device either retrieved or created from the db
    def get_create_device(self, mac):
        try:
            return Device.get(Device.mac == mac)
        except Device.DoesNotExist:
            return Device.create(mac=mac)

    # ensure our mac addr is colon separated
    def normalise_mac(self, mac):
        return mac.replace('-',':')

    # qualify user with local_domain if there is no '@' symbol
    def qualify_user(self, user):
        if '@' not in user:
            return user + '@' + LOCAL_DOMAIN
        else:
            return user

    # parse an incoming message
    def parse_msg(self, msg):
        # print our full message for debug logs
        logging.debug("MSG: logger %s supplied log '%s'" % (self.client_address[0], msg) )

        # run a re.search() using the regex defined for our client
        params = LOGGER_DEFINITIONS[self.client_address[0]].search(msg)

        if params is None:
            # do nothing if no pattern matches, unsupported log line
            return False
        elif "mac" in params.groupdict():
            # get our device object
            client = self.get_create_device( self.normalise_mac( params.group('mac') ))

            # create a datetime object
            dt = datetime.now()

            # set ip if it exists in our params
            if "ip" in params.groupdict():
                client.ip = params.group('ip')
                logging.info( "MAP: logger %s supplied mac %s --> ip %s at timestamp (%s)" % (self.client_address[0], client.mac, client.ip, dt) )

            # set user if it exists in our params
            if "user" in params.groupdict():
                client.user = self.qualify_user( params.group('user') )
                logging.info( "MAP: logger %s supplied mac %s --> user %s at timestamp (%s)" % (self.client_address[0], client.mac, client.user, dt) )

            # update timestamp of entry and save
            # TODO: Check if db update was successful or error with reason
            client.timestamp = dt
            client.save()

            # now if we have both a user and ip defined update the firewall
            if client.user and client.ip:
                UIDQ.put((client.user, client.ip))
            # TODO: consider unfinished map logging message
        else:
            # pattern matches but no 'mac' group defined
            logging.warning( "MAP: logger %s pattern '%s' does not define a 'mac' group" % (self.client_address[0], LOGGER_DEFINITIONS[self.client_address[0]].pattern()) )
            return False

    def handle(self):
        data = bytes.decode(self.request[0].strip())
        socket = self.request[1]

        # parse incoming message
        self.parse_msg(str(data))

if __name__ == "__main__":
    try:
        # initialise the table incase it's not already initalised
        Device.create_table(fail_silently=True)

        # Attempt a connection to our palo alto firewall
        try:
            PAFW = PanDevice.create_from_device(PA_HOSTNAME, PA_USERNAME, PA_PASSWORD)
            pass
        except Exception as e:
            logging.error( "PAN: failed to connect to palo alto host %s" % (PA_HOSTNAME) )
            raise
        else:
            logging.debug( "PAN: successfully connected to palo alto host %s" % (PA_HOSTNAME) )

        # start our uid updater worker
        try:
            uid_worker = PA_UID_Update_Worker(PAFW, UIDQ, TIMEOUT)
            uid_worker.setDaemon(True)
            uid_worker.start()
        except Exception as e:
            logging.error( "SYSTEM: failed to start UID Update Worker thread (%s)" % (e) )
            raise
        else:
            logging.debug( "SYSTEM: successfully created UID Update Worker thread")

        # start our network server
        try:
            server = PA_UID_UDP_Server((LISTEN_HOST,LISTEN_PORT), PA_UID_UDP_Handler)
            logging.info( "SYSTEM: starting uid message listening servers")
            server.serve_forever(poll_interval=0.5)
        except IOError as e:
            logging.error( "SYSTEM: IO exception encountered while starting uid server (%s) shutting down" % (e) )
            UIDQ.join()
            DB.stop()
            raise
    except (KeyboardInterrupt, SystemExit):
        logging.info( "SYSTEM: encountered interrupt/system exit - shutting down")
        server.shutdown()
        UIDQ.join()
        DB.stop()
    except Exception as e:
        logging.info( "SYSTEM: exception encountered during operation (%s) shutting down" % (e))
        server.shutdown()
        UIDQ.join()
        DB.stop()
        raise
