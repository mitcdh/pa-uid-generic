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
from __future__ import print_function
import logging
import SocketServer
import re
import os

from datetime import datetime
from peewee import *
from playhouse.sqliteq import SqliteQueueDatabase
from pandevice.base import PanDevice

# Variables to take from os environment
PA_HOSTNAME = os.environ['PA_HOSTNAME']
PA_USERNAME = os.environ['PA_USERNAME']
PA_PASSWORD = os.environ['PA_PASSWORD']
LISTEN_HOST = os.environ.get('LISTEN_HOST','0.0.0.0')
LISTEN_PORT = int(os.environ.get('LISTEN_PORT','1514'))
LOCAL_DOMAIN = os.environ.get('LOCAL_DOMAIN','')
DB = SqliteQueueDatabase(os.environ.get('DB_PATH','device.db'))

# define our loggers and their associated regex
LOGGER_DEFINITIONS = {
    '10.0.0.1': re.compile('DHCP lease started ip (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) --> mac (?P<mac>(?:[0-9a-fA-F][0-9a-fA-F]:){5}(?:[0-9a-fA-F][0-9a-fA-F]))'),
    '10.0.0.2': re.compile('Login OK: \[(?P<user>.+?)\] \(from client \S+ port \d+ cli (?P<mac>(?:[0-9a-fA-F][0-9a-fA-F]-){5}(?:[0-9a-fA-F][0-9a-fA-F])) via TLS tunnel\)'),
    '10.0.0.3': re.compile('Login OK: \[(?P<user>.+?)\] \(from client \S+ port \d+ cli (?P<mac>(?:[0-9a-fA-F][0-9a-fA-F]-){5}(?:[0-9a-fA-F][0-9a-fA-F])) via TLS tunnel\)')
}

# Create a connection to our palo alto firewall
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
        return client_address[0] in LOGGER_DEFINITIONS


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
            return user + LOCAL_DOMAIN
        else:
            return user

    # parse an incoming message
    def parse_msg(self, msg):
        # run a re.search() using the regex defined for our client
        params = LOGGER_DEFINITIONS[self.client_address[0]].search(msg)

        if params is None:
            # do nothing if no pattern matches
            return False
        elif "mac" in params.groupdict():
            # get our device object
            device = self.get_create_device( self.normalise_mac( params.group('mac') ))

            # set ip if it exists in our params
            if "ip" in params.groupdict():
                device.ip = params.group('ip')
                print( "%s : supplied mac/ip map [%s <-> %s]" % (self.client_address[0], device.mac, device.ip))

            # set user if it exists in our params
            if "user" in params.groupdict():
                device.user = self.qualify_user( params.group('user') )
                print( "supplied mac/user map [%s <-> %s]" % (self.client_address[0], device.mac, device.user))

            # update timestamp of entry and save
            device.timestamp = datetime.now()
            device.save()

            # now if we have both a user and ip defined update the firewall
            if device.user and device.ip:
                PAFW.userid.login(device.user, device.ip)
        else:
            # if nothing matches we have an unsupported pattern
            return False

    def handle(self):
        data = bytes.decode(self.request[0].strip())
        socket = self.request[1]
        #print( "%s : " % self.client_address[0], str(data))

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
