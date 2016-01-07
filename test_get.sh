#!/usr/bin/python

import requests

DIORITE_URL           = 'https://judy.puppet.soton.ac.uk::5000/getcert/user'
DIORITE_SSL_CA_FILE   = '/etc/puppetlabs/puppet/ssl/certs/ca.pem'
USERNAME              = 'user'
PASSWORD              = 'pass'
HOSTNAME              = 'test.soton.ac.uk'
IDENT                 = 'el7s'

payload = {'hostname': HOSTNAME, 'username': USERNAME, 'password': PASSWORD, 'ident': IDENT}
r = requests.post(DIORITE_URL, data=payload, verify = DIORITE_SSL_CA_FILE)
