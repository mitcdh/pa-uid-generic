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
    python2
    peewee
    pandevice

Environment Variables:
    PA_HOSTNAME: hostname or ip of the palo alto firewall (required)
    PA_USERNAME: username for account with at a minimum "Operational Requests" and "User-ID Agent" permitted on the Palo Alto firewall (required)
    PA_PASSWORD: password for account (required)
    LISTEN_HOST: ip to listen for log traffic on
    LISTEN_PORT: port to listen for log traffic on (currently UDP only)
    LOCAL_DOMAIN: domain to append to user when not fully qualified
    DB_PATH: path for sqlite database
    LOG_LEVEL: log level passed into pythons logging config
    WORKER_TIMEOUT: base timeout if api requests to pa fail temporarily
    UPDATE_MIN: timeout between updates of PA
"""
import logging
import SocketServer
import re
import os
import time
import Queue

from datetime import (datetime, timedelta)
from threading import Thread

from peewee import *
from playhouse.sqliteq import SqliteQueueDatabase
from pandevice.base import PanDevice
from pandevice.errors import PanDeviceError

# logging configuration
logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s',
                    level=os.environ.get("LOG_LEVEL", "INFO"))

# import our loggers and their associated regex from logger_definitions.py
try:
    from logger_definitions import LOGGER_DEFINITIONS
except ImportError as e:
    logging.error("CONFIG: failed to import LOGGER_DEFINITIONS from 'logger_definitions.py'")
    raise
else:
    logging.debug("CONFIG: imported LOGGER_DEFINITIONS from 'logger_definitions.py'")

# Variables to take from os environment
LISTEN_HOST = os.environ.get('LISTEN_HOST', '0.0.0.0')
LISTEN_PORT = int(os.environ.get('LISTEN_PORT', '1514'))
LOCAL_DOMAIN = os.environ.get('LOCAL_DOMAIN', '')
DB_PATH = os.environ.get('DB_PATH', 'device.db')
WORKER_TIMEOUT = int(os.environ.get('WORKER_TIMEOUT', '5'))
UPDATE_MIN = int(os.environ.get('UPDATE_MIN', '5'))

# palo alto connection must be defined
try:
    PA_HOSTNAME = os.environ['PA_HOSTNAME']
    PA_USERNAME = os.environ['PA_USERNAME']
    PA_PASSWORD = os.environ['PA_PASSWORD']
except KeyError as e:
    logging.error("CONFIG: required environment config variable %s is undefined"
                  % (e))
    raise
else:
    logging.debug("CONFIG: All PA_ environment variables defined")

# create our database in meta
# Would defer but OperationalError exceptions are raised in thread
try:
    DB = SqliteQueueDatabase(DB_PATH)
except Exception:
    logging.error("DB: failed to create SqliteQueueDatabase instance for path %s"
                  % (DB_PATH))
    raise
else:
    logging.debug("DB: successfully created SqliteQueueDatabase instance at path %s"
                  % (DB_PATH))

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
        super(PA_UID_Update_Worker, self).__init__(name="PA_UID_Update_Worker")
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
                except PanDeviceError as e:
                    logging.error("UID: [Queue Size: %s] pan host %s temporarily failed update with exception (%s) pausing worker for %ss"
                                  % (self.q.qsize(), PA_HOSTNAME, e, self.timeout))
                    self.q.put((user, ip))
                    self.q.task_done()
                    time.sleep(self.current_timeout)
                    self.current_timeout = self.current_timeout * 2
                except Exception as e:
                    logging.error("UID: [Queue Size: %s] pan host %s permanently failed update for map ip %s --> user %s (%s) removed from queue"
                                  % (self.q.qsize(), PA_HOSTNAME, ip, user, e))
                    self.q.task_done()
                else:
                    logging.info("UID: [Queue Size: %s] pan host %s updated with map ip %s --> user %s"
                                 % (self.q.qsize(), PA_HOSTNAME, ip, user))
                    self.q.task_done()
                    self.current_timeout = self.timeout
            except Queue.Empty:
                pass
            except Exception:
                raise


# Customised so we can ignore from hosts we haven't defined a pattern for
class PA_UID_UDP_Server(SocketServer.ThreadingUDPServer):
    def verify_request(self, request, client_address):
        if client_address[0] in LOGGER_DEFINITIONS:
            return True
        else:
            logging.debug("MSG: received message from %s with no associated logger definition"
                          % (client_address[0]))
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
        return mac.replace('-', ':')

    # qualify user with local_domain if there is no '@' symbol
    def qualify_user(self, user):
        if '@' not in user:
            return user + '@' + LOCAL_DOMAIN
        else:
            return user

    # return a string "null" for empty str
    def null_string(self, str):
        if not str:
            return "null"
        else:
            return str

    # boolean test if a user/ip map is complete
    def complete_device(self, client):
        if client.user and client.ip:
            return True
        else:
            return False

    # convert td to minutes and handle division by 0
    def td_minutes(self, td):
        seconds = td.total_seconds()
        if seconds != 0:
            return seconds / 60
        else:
            return 0

    # parse an incoming message
    def parse_msg(self, msg):
        # print our full message for debug logs
        logging.debug("MSG: logger %s supplied log '%s'"
                      % (self.client_address[0], msg))

        # run a re.search() using the regex defined for our client
        params = LOGGER_DEFINITIONS[self.client_address[0]].search(msg)

        if params is None:
            # do nothing if no pattern matches, unsupported log line
            return False
        elif "mac" in params.groupdict():
            # get our device object
            msg_mac = self.normalise_mac(params.group('mac'))
            client = self.get_create_device(msg_mac)
            updated = False

            # create a datetime object
            dt = datetime.now()

            if "ip" in params.groupdict():
                # set ip if it exists in our params
                msg_ip = params.group('ip')
                logging.debug("MAP: logger %s supplied mac %s --> ip %s"
                              % (self.client_address[0], msg_mac, msg_ip))
                if msg_ip != client.ip:
                    logging.info("DB: updating mac %s --> ip %s with new ip %s"
                                 % (msg_mac, self.null_string(client.ip), msg_ip))
                    client.ip = msg_ip
                    updated = True
            elif "user" in params.groupdict():
                # set user if it exists in our params
                msg_user = self.qualify_user(params.group('user'))
                logging.debug("MAP: logger %s supplied mac %s --> user %s"
                              % (self.client_address[0], msg_mac, msg_user))
                if msg_user != client.user:
                    logging.info("DB: updating mac %s --> user %s with new user %s"
                                 % (msg_mac, self.null_string(client.user), msg_user))
                    client.user = msg_user
                    updated = True
            else:
                # warn if no user/ip found
                logging.warning("MAP: logger %s supplied mac %s but no user/ip match found"
                                % (self.client_address[0], msg_mac))

            # get a timedelta
            td = dt - client.timestamp

            # now if we have both a user and ip defined update the firewall
            if self.complete_device(client) and (updated or (self.td_minutes(td) > UPDATE_MIN)):
                UIDQ.put((client.user, client.ip))

            # update timestamp of entry
            client.timestamp = dt

            # save our new client
            try:
                client.save()
            except Exception:
                logging.error("DB: exception encountered while updating db %s entry for mac %s"
                              % (DB_PATH, msg_mac))
                raise

        else:
            # pattern matches but no 'mac' group defined
            logging.warning("MAP: logger %s pattern '%s' does not define a 'mac' group"
                            % (self.client_address[0], LOGGER_DEFINITIONS[self.client_address[0]].pattern()))
            return False

    def handle(self):
        data = bytes.decode(self.request[0].strip())

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
            logging.error("PAN: failed to connect to palo alto host %s"
                          % (PA_HOSTNAME))
            raise
        else:
            logging.debug("PAN: successfully connected to palo alto host %s"
                          % (PA_HOSTNAME))

        # start our uid updater worker
        try:
            uid_worker = PA_UID_Update_Worker(PAFW, UIDQ, WORKER_TIMEOUT)
            uid_worker.setDaemon(True)
            uid_worker.start()
        except Exception as e:
            logging.error("SYSTEM: failed to start UID Update Worker thread (%s)"
                          % (e))
            raise
        else:
            logging.debug("SYSTEM: successfully created UID Update Worker thread")

        # start our network server
        try:
            server = PA_UID_UDP_Server((LISTEN_HOST, LISTEN_PORT), PA_UID_UDP_Handler)
            logging.info("SYSTEM: starting uid message listening servers")
            server.serve_forever(poll_interval=0.5)
        except IOError as e:
            logging.error("SYSTEM: IO exception encountered while starting uid server (%s) shutting down"
                          % (e))
            UIDQ.join()
            DB.stop()
            raise
    except (KeyboardInterrupt, SystemExit):
        logging.info("SYSTEM: encountered interrupt/system exit shutting down")
        server.shutdown()
        UIDQ.join()
        DB.stop()
    except Exception as e:
        logging.info("SYSTEM: exception encountered during operation (%s) shutting down"
                     % (e))
        server.shutdown()
        UIDQ.join()
        DB.stop()
        raise
