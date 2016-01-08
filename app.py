#!/usr/bin/python
# Version 2016-01-08-10

OPTIONS_FILE        = '/data/diorite/options.conf'

## DO NOT EDIT PAST THIS LINE #################################################
from flask import Flask, jsonify, abort, request, g
import subprocess
import ldap
import syslog
import re
import os.path
import grp
import ConfigParser
import requests

app = Flask(__name__)

@app.route('/getcert/user', methods=['POST'])
def getcert_user():
	hostname = request.form['hostname']
	username = request.form['username']
	password = request.form['password']
	ident    = request.form.get('ident','none')

	## authentication 
	if not auth_user(username,password):
		abort(403)

	# authorisation
	if not allowed_user(username):
		abort(403)

	syslog.syslog("received certificate request for " + hostname + " from authorised user " + username)

	return getcert(hostname,ident)

@app.route('/getcert/vmid', methods=['POST'])
def getcert_vuuid():
	## Get a cert by passing in the VMware UUID

	hostname = request.form['hostname']
	uuid     = request.form['uuid']
	ident    = request.form.get('ident','none')

	## TODO authenticate the UUID
	abort(501)

	## TODO authorise the UUID - e.g. check its hostname agains the hostname we got a request for

	return getcert(hostname,ident)

@app.route('/')
def default():
	abort(400)

@app.before_request
def before_request():
	syslog.openlog("diorite")

	## Load config for every request (so no reloads are required just for a config change)
	try:
		g.config = ConfigParser.RawConfigParser()
		g.config.read(OPTIONS_FILE)

		## Diorite config
		if not g.config.has_section('diorite'):
			syslog.syslog("error: [diorite] section missing from diorite options file")
			abort(500)
		else:
			## try to load diorite settings. cfg_get loads from g.config. It accepts a default if no config was found, aborts if no config option is found
			## and no default set either.
			g.puppet_binary       = cfg_get('diorite','puppet_binary','/opt/puppetlabs/bin/puppet')
			g.puppet_confdir      = cfg_get('diorite','puppet_confdir','/etc/puppetlabs/puppet/')
			g.puppet_ssldir       = cfg_get('diorite','puppet_ssldir','/etc/puppetlabs/puppet/ssl/')
			g.ldap_uri            = cfg_get('diorite','ldap_uri')
			g.ldap_search_base    = cfg_get('diorite','ldap_search_base')
			g.ldap_user_attribute = cfg_get('diorite','ldap_user_attribute', 'cn')
			g.access_group        = cfg_get('diorite','access_group','root')

		## ENC config
		if g.config.has_section('enc'):
			g.enc = True

			try:
				g.enc_url        = g.config.get('enc', 'url')
				g.enc_auth_token = g.config.get('enc', 'auth_token')

				if g.config.has_option('enc', 'ssl_verify'):
					g.enc_ssl_verify = g.config.getboolean('enc', 'ssl_verify')
				else:
					g.enc_ssl_verify = True

			except Exception as ex:
				g.enc = False
				syslog.syslog("warning: could not read enc options, disabling enc updating: " + str(ex))
		else:
			g.enc = False

	except Exception as ex:
		syslog.syslog("error: could not read from options file: " + str(ex))
		abort(500)

		
def getcert(hostname,ident):
	## validate the certname 
	if not is_valid_hostname(hostname):
		abort(400)

	## do all the files already exist for this cert name?
	if not all([os.path.exists(g.puppet_ssldir + "private_keys/" + hostname + ".pem"),
			os.path.exists(g.puppet_ssldir + "public_keys/"  + hostname + ".pem"),
			os.path.exists(g.puppet_ssldir + "ca/signed/"    + hostname + ".pem")]):

		## try to clean the cert but fail silently if it doesnt work
		# trying a lot of different methods  cos puppet sux. # http://superuser.com/questions/784471/how-to-reject-certificate-request-on-puppet-master
		sysexec(g.puppet_binary + " cert --confdir " + g.puppet_confdir + " clean " + hostname,shell=True)
		sysexec(g.puppet_binary + " cert --confdir " + g.puppet_confdir + " destroy " + hostname,shell=True)
		sysexec(g.puppet_binary + " ca --confdir " + g.puppet_confdir + " destroy " + hostname,shell=True)

		syslog.syslog("generating new puppet certificate for " + hostname)

		## puppet generate a new cert
		(rcode, stdout, stderr) = sysexec(g.puppet_binary + " cert --confdir " + g.puppet_confdir + " generate " + hostname,shell=True)	

		if rcode != 0:
			syslog.syslog("puppet cert generate failed for hostname " + hostname)
			syslog.syslog("stdout: " + str(stdout))
			syslog.syslog("stderr: " + str(stderr))
			abort(500)
	else:
		syslog.syslog("deploying existing puppet certificate for " + hostname)

	## get a dict ready for json return
	data = {}

	## grab the contents of the files the client needs
	try:
		with open(g.puppet_ssldir + "public_keys/" + hostname + ".pem","r") as f:
			data['public_key'] = f.read()
	except Exception as ex:
		syslog.syslog("failed to read generated public key file for " + hostname)
		syslog.syslog(str(ex))
		abort(500)

	try:
		with open(g.puppet_ssldir + "ca/signed/" + hostname + ".pem","r") as f:
			data['cert'] = f.read()
	except Exception as ex:
		syslog.syslog("failed to read generated certificate file for " + hostname)
		syslog.syslog(str(ex))
		abort(500)

	try:
		with open(g.puppet_ssldir + "private_keys/" + hostname + ".pem","r") as f:
			data['private_key'] = f.read()
	except Exception as ex:
		syslog.syslog("failed to read generated certificate file for " + hostname)
		syslog.syslog(str(ex))
		abort(500)

	## Tell an ENC endpoint (Cortex) that a node exists and so should have a record of it
	## but only if we've been configured to do that
	if g.enc:
		try:
			r = requests.post(g.enc_url + '/' + hostname, data={'auth_token': g.enc_auth_token}, verify=g.enc_ssl_verify)

			if not r.return_code in [200,201]:
				syslog.syslog("warning: error code recieved from enc registration API: " + str(r.return_code))		
		except Exception as ex:
			syslog.syslog("warning: an error occured when contacting the enc: " + str(ex))

	## Load in options from the options file. We silently fail here if something goes wrong.
	try:
		## don't allow the client to send 'diorite' and read diorite core configuration options
		if not ident in ['diorite','enc']:

			## See if the config file has a section matching the supplied ident
			if config.has_section(ident):

				## It does! So load in the data to send to the client.
				options = config.options(ident)
				for opt in options:
					# Don't overwrite puppet cert data
					if opt not in ['public_key','cert','private_key']:
						data[opt] = config.get(ident,opt)

	except Exception as ex:
		syslog.syslog("warning: error loading options for client " + hostname)
		syslog.syslog(str(ex))

	## send results back as json
	return jsonify(data)

def sysexec(command,shell=False):

	try:
		proc = subprocess.Popen(command,stdout=subprocess.PIPE, stderr=subprocess.STDOUT,shell=shell)
		(stdoutdata, stderrdata) = proc.communicate()
		return (proc.returncode,str(stdoutdata),str(stderrdata))
	except Exception as ex:
		syslog.syslog("sysexec exception: " + str(ex))
		return (1,"",str(ex))

def auth_user(username,password):
	if username == '':
		syslog.syslog("username not sent")
		return False
	if password == '':
		syslog.syslog("password not sent")
		return False

	## connect to LDAP and turn off referals
	l = ldap.initialize(g.ldap_uri)
	l.set_option(ldap.OPT_REFERRALS, 0)

	## and bind to the server with a username/password if needed in order to search for the full DN for the user who is logging in.
	try:
		l.simple_bind_s()
	except ldap.LDAPError as e:
		syslog.syslog("Could not bind to LDAP: " + str(e))
		return False

	## Now search for the user object to bind as
	try:
		results = l.search_s(g.ldap_search_base, ldap.SCOPE_SUBTREE,(g.ldap_user_attribute) + "=" + username)
	except ldap.LDAPError as e:
		syslog.syslog("user not found")
		return False

	## handle the search results
	for result in results:
		dn	= result[0]
		attrs	= result[1]

		if dn == None:
			## No dn returned. Return false.
			syslog.syslog("dn not sent")
			return False

		else:
			## Found the DN. Yay! Now bind with that DN and the password the user supplied
			try:
				lauth = ldap.initialize(g.ldap_uri)
				lauth.set_option(ldap.OPT_REFERRALS, 0)
				lauth.simple_bind_s( (dn), (password) )
				return True
			except ldap.LDAPError as e:
				syslog.syslog(str(e))
				syslog.syslog("password wrong " + dn + " " + username + " " + password)
				return False

	## Catch all return false for LDAP auth
	syslog.syslog("catchall")
	return False

def allowed_user(username):
	try:
		agrp = grp.getgrnam(g.access_group)
	except KeyError as ex:
		syslog.syslog("could not find access group " + g.access_group)
		return False

	if username in agrp.gr_mem:
		syslog.syslog("granting access to authorised user " + username)
		return True
	else:
		syslog.syslog("denying access to non-authorised user " + username)
		return False
	

def is_valid_hostname(hostname):
	if len(hostname) > 255:
		return False
	if hostname[-1] == ".":
		hostname = hostname[:-1]
	allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
	return all(allowed.match(x) for x in hostname.split("."))

def cfg_get(section,key,default=None):
	if g.config.has_option(section,key):
		return g.config.get(section,key)
	else:
		if not default is None:
			return default
		else:
			syslog.syslog("missing configuration option in section [diorite]: " + key)
			abort(500)

if __name__ == '__main__':
	app.debug = True
	app.run()
