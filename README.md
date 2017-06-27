# PA Generic User-ID Updater

This is a quick python script allowing regular expressions to be defined to process generic UDP messages (e.g. UDP syslog) for usernames, ip, and mac addresses.

The script assumes mac addresses will be included in all messages and when a full user<->mac<->ip address mapping is formed will send a User-ID update to the configured palo alto firewall.

### Requirements
A requirements.txt has been provided from a pip freeze of a working copy.
* python2
* peewee
* pandevice

### Environment Variables
* `PA_HOSTNAME`: hostname or ip of the palo alto firewall
* `PA_USERNAME`: username for account with at a minimum "Operational Requests" and "User-ID Agent" permitted on the Palo Alto firewall.
* `PA_PASSWORD`: password for account
* `LISTEN_HOST`: ip to listen for log traffic on
* `LISTEN_PORT`: port to listen for log traffic on (currently UDP only)
* `LOCAL_DOMAIN`: domain to append to user when not fully qualified
* `DB_PATH`: path for sqlite database
* `LOG_LEVEL`: log level passed into pythons logging config

### Usage
#### Native
````
# install python requirements
pip install peewee pandevice

# define loggers
cp logger_definitions.py-sample logger_definitions.py

# export required env
export PA_HOSTNAME=10.0.0.1
export PA_USERNAME=uid-user
export PA_PASSWORD=uid-user
export LISTEN_HOST=0.0.0.0
export LISTEN_PORT=1514
export LOCAL_DOMAIN=mydomain.com
export DB_PATH=device.db
export LOG_LEVEL=INFO

python2 ./pa-uid-generic.py
````

#### Systemd
An example unit file has been included at [systemd/pa-uid-generic.service-sample](systemd/pa-uid-generic.service-sample), requires environment variables to be defined in a file named '[env](env-sample)'.

#### Docker
````
# requires environment variables to be defined in a file named 'env' and 'logger_definitions.py' to be defined
docker build -f docker/Dockerfile -t pa-uid-generic .
docker run -d --env-file env -p 1514:1514/udp -v logger_definitions.py:/app/pa-uid-generic/logger_definitions.py pa-uid-generic
````

### Todo
* Graceful failure for other modules and incoming environment variables, currently relying on uncaught exceptions

### Credits
* [marcelom/pysyslog.py](https://gist.github.com/marcelom/4218010) for an implementation of syslog in python.
