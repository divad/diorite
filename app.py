#!/usr/bin/python

from flask import Flask, jsonify, abort, request
import subprocess
import ldap
import syslog
import re
import os.path
import grp

PUPPET_BINARY       = '/opt/puppetlabs/bin/puppet'
PUPPET_CONFDIR      = '/etc/puppetlabs/puppet/'
PUPPET_SSL_ROOT     = '/etc/puppetlabs/puppet/ssl/'
LDAP_URI            = "ldaps://nlbldap.soton.ac.uk"
LDAP_SEARCH_BASE    = 'dc=soton,dc=ac,dc=uk'
LDAP_USER_ATTRIBUTE = 'cn'
ACCESS_GROUP        = 'srvadm'

app = Flask(__name__)
app.debug = True

@app.route('/getcert/user', methods=['POST'])
def getcert_user():
	hostname = request.form['hostname']
	username = request.form['username']
	password = request.form['password']

	## authentication 
	if not auth_user(username,password):
		abort(403)

	# authorisation
	if not allowed_user(username):
		abort(403)

	## validate the certname 
	if not is_valid_hostname(hostname):
		abort(400)

	syslog.syslog("certificate request for " + hostname + " from authorised user " + username)

	## do all the files already exist for this cert name?
	if not all([os.path.exists(PUPPET_SSL_ROOT + "private_keys/" + hostname + ".pem"),
			os.path.exists(PUPPET_SSL_ROOT + "public_keys/"  + hostname + ".pem"),
			os.path.exists(PUPPET_SSL_ROOT + "ca/signed/"    + hostname + ".pem")]):

		## They don't, so clean and generate

		## try to clean the cert but fail silently if it doesnt work
		# trying a lot of different methods  cos, you know, puppet sucks. # http://superuser.com/questions/784471/how-to-reject-certificate-request-on-puppet-master
		sysexec(PUPPET_BINARY + " cert --confdir " + PUPPET_CONFDIR + " clean " + hostname,shell=True)
		sysexec(PUPPET_BINARY + " cert --confdir " + PUPPET_CONFDIR + " destroy " + hostname,shell=True)
		sysexec(PUPPET_BINARY + " ca --confdir " + PUPPET_CONFDIR + " destroy " + hostname,shell=True)

		syslog.syslog("generating new puppet certificate for " + hostname)

		## puppet generate a new cert
		(rcode, stdout, stderr) = sysexec(PUPPET_BINARY + " cert --confdir " + PUPPET_CONFDIR + " generate " + hostname,shell=True)	

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
		with open(PUPPET_SSL_ROOT + "public_keys/" + hostname + ".pem","r") as f:
			data['public_key'] = f.read()
	except Exception as ex:
		syslog.syslog("failed to read generated public key file for " + hostname)
		syslog.syslog(str(ex))
		abort(500)	

	try:
		with open(PUPPET_SSL_ROOT + "ca/signed/" + hostname + ".pem","r") as f:
			data['cert'] = f.read()
	except Exception as ex:
		syslog.syslog("failed to read generated certificate file for " + hostname)
		syslog.syslog(str(ex))
		abort(500)

	try:
		with open(PUPPET_SSL_ROOT + "private_keys/" + hostname + ".pem","r") as f:
			data['private_key'] = f.read()
	except Exception as ex:
		syslog.syslog("failed to read generated certificate file for " + hostname)
		syslog.syslog(str(ex))
		abort(500)

	## send results back as json
	return jsonify(data)

@app.route('/getcert/psk', methods=['POST'])
def getcert_psk():
	pass

@app.route('/getcert/mid', methods=['POST'])
def getcert_machineid():
	pass

@app.route('/')
def default():
	abort(400)

@app.before_request
def before_request():
	syslog.openlog("diorite")

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
	l = ldap.initialize(LDAP_URI)
	l.set_option(ldap.OPT_REFERRALS, 0)

	## and bind to the server with a username/password if needed in order to search for the full DN for the user who is logging in.
	try:
		l.simple_bind_s()
	except ldap.LDAPError as e:
		syslog.syslog("Could not bind to LDAP: " + str(e))
		return False

	## Now search for the user object to bind as
	try:
		results = l.search_s(LDAP_SEARCH_BASE, ldap.SCOPE_SUBTREE,(LDAP_USER_ATTRIBUTE) + "=" + username)
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
				lauth = ldap.initialize(LDAP_URI)
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
		agrp = grp.getgrnam(ACCESS_GROUP)
	except KeyError as ex:
		syslog.syslog("could not find access group " + ACCESS_GROUP)
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

if __name__ == '__main__':
	app.run()
