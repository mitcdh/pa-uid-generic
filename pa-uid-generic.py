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

from datetime import datetime
from peewee import *
from playhouse.sqliteq import SqliteQueueDatabase
from pandevice.base import PanDevice

# Variables to take from os environment
# TODO: Check if required env are defined and gracefully error
PA_HOSTNAME = os.environ['PA_HOSTNAME']
PA_USERNAME = os.environ['PA_USERNAME']
PA_PASSWORD = os.environ['PA_PASSWORD']
LISTEN_HOST = os.environ.get('LISTEN_HOST','0.0.0.0')
LISTEN_PORT = int(os.environ.get('LISTEN_PORT','1514'))
LOCAL_DOMAIN = os.environ.get('LOCAL_DOMAIN','')
logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=os.environ.get("LOG_LEVEL", "INFO"))
DB = SqliteQueueDatabase(os.environ.get('DB_PATH','device.db'))

# import our loggers and their associated regex from logger_definitions.py
# TODO: Check if logger_definitions are defined and gracefully error/quit if not
from logger_definitions import LOGGER_DEFINITIONS

# Create a connection to our palo alto firewall
# TODO: Check connection was successful and gracefully error/quit if not
PAFW = PanDevice.create_from_device(PA_HOSTNAME, PA_USERNAME, PA_PASSWORD)

# PeeWee Object Definition
class Device(Model):
    mac = CharField(unique=True)
    user = CharField(default="")
    ip = CharField(default="")
    timestamp = DateTimeField(default=datetime.now())

    class Meta:
        database = DB

# Customised so we can ignore from hosts we haven't defined a pattern for
class PA_UID_Server(SocketServer.ThreadingUDPServer):
    def verify_request(self, request, client_address):
        if client_address[0] in LOGGER_DEFINITIONS:
            return True
        else:
            logging.debug("UNDEFINED_LOGGER: received message from %s with no associated logger definition" % (client_address[0]) )
            return False


class PA_UID_UDPHandler(SocketServer.BaseRequestHandler):
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
        logging.debug("LOG_RECEIVED: logger %s supplied log '%s'" % (self.client_address[0], msg) )

        # run a re.search() using the regex defined for our client
        params = LOGGER_DEFINITIONS[self.client_address[0]].search(msg)

        if params is None:
            # do nothing if no pattern matches, unsupported log line
            return False
        elif "mac" in params.groupdict():
            # get our device object
            device = self.get_create_device( self.normalise_mac( params.group('mac') ))

            # create a datetime object
            dt = datetime.now()

            # set ip if it exists in our params
            if "ip" in params.groupdict():
                device.ip = params.group('ip')
                logging.info( "MAP_UPDATED: logger %s supplied mac %s --> ip %s at timestamp (%s)" % (self.client_address[0], device.mac, device.ip, dt) )

            # set user if it exists in our params
            if "user" in params.groupdict():
                device.user = self.qualify_user( params.group('user') )
                logging.info( "MAP_UPDATED: logger %s supplied mac %s --> user %s at timestamp (%s)" % (self.client_address[0], device.mac, device.user, dt) )

            # update timestamp of entry and save
            # TODO: Check if db update was successful or error with reason
            device.timestamp = dt
            device.save()

            # now if we have both a user and ip defined update the firewall
            if device.user and device.ip:
                # TODO: Check if api update was successful or error with reason
                PAFW.userid.login(device.user, device.ip)
                logging.info( "PA_UPDATED: host %s updated with map ip %s --> user %s from timestamp (%s)" % (PA_HOSTNAME, device.ip, device.user, dt))
            # TODO: consider unfinished map logging message
        else:
            # pattern matches but no 'mac' group defined
            logging.warning( "MAP_ERROR: logger %s pattern '%s' does not define a 'mac' group" % (self.client_address[0], LOGGER_DEFINITIONS[self.client_address[0]].pattern()) )
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

        # start our network server
        server = PA_UID_Server((LISTEN_HOST,LISTEN_PORT), PA_UID_UDPHandler)
        server.serve_forever(poll_interval=0.5)
    except (IOError, SystemExit):
        # stop our SqliteQueueDatabase
        DB.stop()
        raise
    except KeyboardInterrupt:
        print ("Crtl+C Pressed. Shutting down.")
        # stop our SqliteQueueDatabase
        DB.stop()
