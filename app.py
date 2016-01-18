#!/usr/bin/python
# Version 2016-01-18-04

CONFIG_FILE        = '/data/diorite/diorite.conf'
OPTIONS_DIR        = '/data/diorite/options/'

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
import yaml

app = Flask(__name__)

################################################################################

@app.route('/')
def default():
	abort(400)

################################################################################

@app.route('/getcert/user', methods=['POST'])
def getcert_user():
	hostname = request.form['hostname']
	username = request.form['username']
	password = request.form['password']
	ident    = request.form.get('ident','default')

	## authentication 
	if not auth_user(username,password):
		abort(403)

	# authorisation
	if not allowed_user(username):
		abort(403)

	syslog.syslog("received certificate request for " + hostname + " from authorised user " + username)

	return getcert(hostname,ident)

################################################################################

@app.route('/getcert/vmid', methods=['POST'])
def getcert_vuuid():
	## Get a cert by passing in the VMware UUID

	hostname = request.form['hostname']
	uuid     = request.form['uuid']
	ident    = request.form.get('ident','none')

	## TODO authenticate the UUID
	# abort with not yet implemented
	abort(501)

	## TODO authorise the UUID - e.g. check its hostname agains the hostname we got a request for

	#return getcert(hostname,ident)

################################################################################

@app.before_request
def before_request():
	syslog.openlog("diorite")

	## Load config for every request (so no reloads are required just for a config change)
	try:
		g.config = ConfigParser.RawConfigParser()
		g.config.read(CONFIG_FILE)

		## Diorite config
		if not g.config.has_section('diorite'):
			syslog.syslog("error: [diorite] section missing from config file")
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

		## default env before we load a default from the config
		g.env = 'production'

		## ENC config
		if g.config.has_section('enc'):
			g.enc = True

			try:
				g.enc_url        = g.config.get('enc', 'url')
				g.enc_auth_token = g.config.get('enc', 'auth_token')

				if g.config.has_option('enc', 'default_environment'):
					g.env = g.config.get('enc', 'default_environment')

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

################################################################################
		
def getcert(hostname,ident):
	"""Executes a command on the local system using subprocess Popen"""

	## validate the certname 
	if not is_valid_hostname(hostname):
		syslog.syslog("Invalid hostname presented to diorite")
		abort(400)

	## validate the ident
	if not is_valid_ident(ident):
		syslog.syslog("Invalid ident presented to diorite")
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
	## but only if we've been configured to do that. It will return an environment which
	## diorite uses to pick what data (options) to send to the client, if any.
	if g.enc:
		try:
			r = requests.post(g.enc_url + '/' + hostname, data={'auth_token': g.enc_auth_token}, verify=g.enc_ssl_verify)

			if not r.status_code == 200:
				syslog.syslog("warning: error code recieved from ENC registration API: " + str(r.return_code))	
			else:
				## Get the yaml response which includes the environment to use
				try:
					response = yaml.load(r.text)
					syslog.syslog("enc returned the environment for " + hostname + " as " + str(response['environment']))
					g.env    = response['environment']
				except Exception as ex:
					syslog.syslog("warning: could not decode yaml response from ENC registration API: " + str(ex))						
	
		except Exception as ex:
			syslog.syslog("warning: an error occured when contacting the enc: " + str(ex))

	## Load in options from the ident file. We silently fail here if something goes wrong.
	try:
		path = os.path.join(OPTIONS_DIR,ident + ".conf")
		if os.path.exists(path):

			iconf = ConfigParser.RawConfigParser()
			iconf.read(CONFIG_FILE)			

			## Load the section for the environment chosen
			if iconf.has_section(g.env):
				options = iconf.options(g.env)
				for opt in options:
					# Don't overwrite puppet cert data
					if opt not in ['public_key','cert','private_key']:
						data[opt] = iconf.get(g.env,opt)
		else:
			syslog.syslog("warning: no ident options file found for " + hostname)			

	except Exception as ex:
		syslog.syslog("warning: error loading options for client " + hostname + ":" + str(ex))

	## send results back as json
	return jsonify(data)

################################################################################

def sysexec(command,shell=False):
	"""Executes a command on the local system using subprocess Popen"""

	try:
		proc = subprocess.Popen(command,stdout=subprocess.PIPE, stderr=subprocess.STDOUT,shell=shell)
		(stdoutdata, stderrdata) = proc.communicate()
		return (proc.returncode,str(stdoutdata),str(stderrdata))
	except Exception as ex:
		syslog.syslog("sysexec exception: " + str(ex))
		return (1,"",str(ex))

################################################################################

def auth_user(username,password):
	"""Authenticates a user using LDAP"""

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

################################################################################

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

################################################################################	

def is_valid_hostname(hostname):
	if len(hostname) > 255:
		return False
	if hostname[-1] == ".":
		hostname = hostname[:-1]
	allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
	return all(allowed.match(x) for x in hostname.split("."))

################################################################################

def is_valid_ident(ident):
	allowed = re.compile("^[A-Z\d_\-]{1,32}$",re.IGNORECASE)
	return allowed.match(ident)

################################################################################

def cfg_get(section,key,default=None):
	if g.config.has_option(section,key):
		return g.config.get(section,key)
	else:
		if not default is None:
			return default
		else:
			syslog.syslog("missing configuration option in section [diorite]: " + key)
			abort(500)

################################################################################

if __name__ == '__main__':
	app.debug = True
	app.run()
