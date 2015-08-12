from flask import Flask, jsonify, abort, request
import subprocess
import ldap
import syslog
import re

PUPPET_BINARY       = '/usr/local/bin/puppet'
PUPPET_SSL_ROOT     = '/etc/puppetlabs/puppet/ssl/'
LDAP_URI            = "ldaps://nlbldap.soton.ac.uk"
LDAP_SEARCH_BASE    = 'dc=soton,dc=ac,dc=uk'
LDAP_USER_ATTRIBUTE = 'cn'

app = Flask(__name__)
app.debug = True

@app.route('/getcert/user', methods=['POST'])
def getcert_user():
	hostname = request.form['hostname']
	username = request.form['username']
	password = request.form['password']

	## auth
	if not auth_user(username,password):
		abort(403)

	## validate the certname 
	# TODO - more validation?
	if not is_valid_hostname(hostname):
		abort(400)

	## puppet clean the existing cert if any
	(rcode, stdout, stderr) = sysexec(PUPPET_BINARY + " cert clean " + hostname,shell=True)

	if rcode != 0:
		syslog.syslog("puppet cert clean failed for hostname " + hostname)
		syslog.syslog("stdout: " + str(stdout))
		syslog.syslog("stderr: " + str(stderr))
		abort(500)

	## puppet generate
	(rcode, stdout, stderr) = sysexec(PUPPET_BINARY + " cert generate " + hostname,shell=True)	

	if rcode != 0:
		syslog.syslog("puppet cert generate failed for hostname " + hostname)
		syslog.syslog("stdout: " + str(stdout))
		syslog.syslog("stderr: " + str(stderr))
		abort(500)

	## get a dict ready for json return
	data = {}

	## grab the contents of the generated files
	try:
		with open(PUPPET_SSL_ROOT + "public_keys/" + hostname + ".pem","r") as f:
			data['public_key'] = f.read()
	except Exception as ex:
		syslog.syslog("failed to read generated public key file for " + hostname)
		syslog.syslog(str(ex))
		abort(500)	

	try:
		with open(PUPPET_SSL_ROOT + "certs/" + hostname + ".pem","r") as f:
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

def is_valid_hostname(hostname):
	if len(hostname) > 255:
		return False
	if hostname[-1] == ".":
		hostname = hostname[:-1]
	allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
	return all(allowed.match(x) for x in hostname.split("."))

if __name__ == '__main__':
	app.run()
