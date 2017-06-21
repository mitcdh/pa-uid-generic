# PA Generic User-ID Updater

This is a quick python script allowing regular expressions to be defined to
process generic UDP messages (e.g. UDP syslog) for usernames, ip, and mac
addresses.

The script assumes mac addresses will be included in all messages and when a
full user<->mac<->ip address mapping is formed will sent a User-ID update to the
configured palo alto firewall

Requires:
  * peewee
  * pandevice

Todo:
  * Lots
