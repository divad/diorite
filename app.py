#!/usr/bin/python
# Version 2016-02-12-02
CONFIG_FILE        = '/data/cortex_puppet_autosign/cortex_puppet_autosign.conf'
PUPPET_BINARY      = '/opt/puppetlabs/bin/puppet'
PUPPET_CONFDIR     = '/etc/puppetlabs/puppet/'
PUPPET_SSLDIR      = '/etc/puppetlabs/puppet/ssl/'
AUTH_TOKEN         = 'changeme'
DEBUG              = False

## DO NOT EDIT PAST THIS LINE #################################################

from flask import Flask, jsonify, abort, request, g
import subprocess
import syslog
import re
import os.path
import ConfigParser
import traceback
import logging

################################################################################

app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_pyfile(CONFIG_FILE,silent=True)
app.logger.setLevel(logging.DEBUG)

################################################################################

@app.route('/')
def default():
	abort(400)

################################################################################

@app.route('/getcert/<hostname>', methods=['GET'])
def register_by_user(hostname):

	if 'X-Auth-Token' not in request.headers:
		syslog.syslog("getcert request failed because X-Auth-Token was missing from the request")
		abort(401)
	if request.headers['X-Auth-Token'] != app.config['AUTH_TOKEN']:
		app.logger.warn('getcert request failed because the X-Auth-Token was incorrect')
		abort(401)

	return getcert(hostname)

################################################################################

@app.before_request
def before_request():
	syslog.openlog("cortex-puppet-autosign")

################################################################################
		
def getcert(hostname):
	"""Get a puppet SSL certficate bundle for a particular hostname"""

	## validate the certname 
	if not is_valid_hostname(hostname):
		syslog.syslog("Invalid hostname in request")
		abort(400)

	## do all the files already exist for this cert name?
	if not all([os.path.exists(g.puppet_ssldir + "private_keys/" + hostname + ".pem"),
			os.path.exists(g.puppet_ssldir + "public_keys/"  + hostname + ".pem"),
			os.path.exists(g.puppet_ssldir + "ca/signed/"    + hostname + ".pem")]):

		## try to clean the cert but fail silently if it doesnt work
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

def is_valid_hostname(hostname):
	"""Returns true if the given hostname is valid"""

	if len(hostname) > 255:
		return False
	if hostname[-1] == ".":
		hostname = hostname[:-1]
	allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
	return all(allowed.match(x) for x in hostname.split("."))

################################################################################

@app.errorhandler(500)
@app.errorhandler(Exception)
def error500(error):
	# Get exception traceback
	if app.debug:
		debug = traceback.format_exc()
	else:
		debug = None

	## send a log about this
	app.logger.error("""
Exception Type:       %s
Exception Message:    %s
HTTP Path:            %s
HTTP Method:          %s
Client IP Address:    %s
User Agent:           %s
User Platform:        %s
User Browser:         %s
User Browser Version: %s

Traceback:

%s

""" % (
			str(type(error)),
			error.__str__(),
			request.path,
			request.method,
			request.remote_addr,
			request.user_agent.string,
			request.user_agent.platform,
			request.user_agent.browser,
			request.user_agent.version,
			debug,	
		))

	return "500 Internal Server Error", 500

################################################################################

if __name__ == '__main__':
	app.run()
