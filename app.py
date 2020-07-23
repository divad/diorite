#!/usr/bin/python
# Version 2016-07-19-01

## the config file to load from
CONFIG_FILE        = '/data/cortex-puppet-bridge/bridge.conf'

## config defaults
PUPPET_BINARY            = '/opt/puppetlabs/bin/puppet'
PUPPETSRV_BINARY         = '/opt/puppetlabs/bin/puppetserver'
PUPPET_CONFDIR           = '/etc/puppetlabs/puppet/'
PUPPET_SSLDIR            = '/etc/puppetlabs/puppet/ssl/'
PUPPET_ENVIRONMENTS_BASE = '/etc/puppetlabs/code/environments'
PUPPET_USER              = 'puppet'
PUPPET_GROUP             = 'puppet'
SAMBA_CONFIG_DIR         = '/etc/samba/conf.d'
SAMBA_BUILD_CMD          = ['/usr/sbin/samba_build_confd']
SAMBA_RESTART_CMD        = ['/usr/bin/systemctl', 'reload', 'smb']
AUTH_TOKEN               = 'changeme'
DEBUG                    = False

## DO NOT EDIT PAST THIS LINE #################################################

from flask import Flask, jsonify, abort, request, g, make_response
import subprocess
import syslog
import re
import os.path
import shutil
import ConfigParser
import traceback
import logging
import yaml
import datetime
import pwd
import grp

################################################################################

app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_pyfile(CONFIG_FILE,silent=True)
app.logger.setLevel(logging.DEBUG)

################################################################################

PUPPET_UID = pwd.getpwnam(PUPPET_USER).pw_uid
PUPPET_GID = grp.getgrnam(PUPPET_GROUP).gr_gid

################################################################################

ENVIRONMENT_NAME_REGEX = re.compile(r"\A[a-z0-9_]+\Z")

################################################################################

@app.route('/')
def default():
	abort(400)

################################################################################

@app.route('/deactivatenode/<hostname>', methods=['GET'])
def deactivate_node(hostname):

	if 'X-Auth-Token' not in request.headers:
		syslog.syslog("deactivatenode request failed because X-Auth-Token was missing from the request")
		abort(401)
	if request.headers['X-Auth-Token'] != app.config['AUTH_TOKEN']:
		app.logger.warn("deactivatenode request failed because the X-Auth-Token was incorrect")
		abort(401)

	## validate the hostname
	if not is_valid_hostname(hostname):
		syslog.syslog("Invalid hostname in request")
		abort(400)

	## deactivate the puppet node
	(rcode, stdout, stderr) = sysexec([app.config['PUPPET_BINARY'], "node", "--confdir", app.config['PUPPET_CONFDIR'], "deactivate", hostname], shell=False)

	if rcode != 0:
		syslog.syslog("puppet node deactivate failed for hostname " + hostname)
		syslog.syslog("stdout: " + str(stdout))
		syslog.syslog("stderr: " + str(stderr))
		abort(500)
	else:
		syslog.syslog("puppet node with hostname " + hostname + " was deactivated")

	# Return blank 200 OK response
	return ""

################################################################################

@app.route('/cleannode/<hostname>', methods=['GET'])
def clean_node(hostname):

	if 'X-Auth-Token' not in request.headers:
		syslog.syslog("cleannode request failed because X-Auth-Token was missing from the request")
		abort(401)
	if request.headers['X-Auth-Token'] != app.config['AUTH_TOKEN']:
		app.logger.warn("cleannode request failed because the X-Auth-Token was incorrect")
		abort(401)

	## validate the hostname
	if not is_valid_hostname(hostname):
		syslog.syslog("Invalid hostname in request")
		abort(400)

	## clean the puppet node
	(rcode, stdout, stderr) = sysexec([app.config['PUPPET_BINARY'], "node", "--confdir", app.config['PUPPET_CONFDIR'], "clean", hostname], shell=False)

	if rcode != 0:
		syslog.syslog("puppet node clean failed for hostname " + hostname)
		syslog.syslog("stdout: " + str(stdout))
		syslog.syslog("stderr: " + str(stderr))
		abort(500)
	else:
		syslog.syslog("puppet node with hostname " + hostname + " was cleaned")

	# Return blank 200 OK response
	return ""

################################################################################

@app.route('/getcert/<hostname>', methods=['GET'])
def register_by_user(hostname):

	if 'X-Auth-Token' not in request.headers:
		syslog.syslog("getcert request failed because X-Auth-Token was missing from the request")
		abort(401)
	if request.headers['X-Auth-Token'] != app.config['AUTH_TOKEN']:
		app.logger.warn('getcert request failed because the X-Auth-Token was incorrect')
		abort(401)

	try:
		puppet_version = get_puppet_version()
	except Exception as e:
		syslog.syslog('Failed to get Puppet version ' + str(e))
		abort(500)

	## validate the certname 
	if not is_valid_hostname(hostname):
		syslog.syslog("Invalid hostname in request")
		abort(400)

	## do all the files already exist for this cert name?
	if not all([os.path.exists(app.config['PUPPET_SSLDIR'] + "private_keys/" + hostname + ".pem"),
			os.path.exists(app.config['PUPPET_SSLDIR'] + "public_keys/"  + hostname + ".pem"),
			os.path.exists(app.config['PUPPET_SSLDIR'] + "ca/signed/"    + hostname + ".pem")]):

		## try to clean the cert but fail silently if it doesnt work
		if puppet_version[0] <= 4:
			sysexec([app.config['PUPPET_BINARY'], "cert", "--confdir", app.config['PUPPET_CONFDIR'], "clean", hostname], shell=False)
			sysexec([app.config['PUPPET_BINARY'], "cert", "--confdir", app.config['PUPPET_CONFDIR'], "destroy", hostname], shell=False)
			sysexec([app.config['PUPPET_BINARY'], "ca", "--confdir", app.config['PUPPET_CONFDIR'], "destroy", hostname], shell=False)
		else:
			sysexec([app.config['PUPPETSRV_BINARY'], "ca", "clean", "--config", os.path.join(app.config['PUPPET_CONFDIR'], "puppet.conf"), "--certname", hostname], shell=False)

		syslog.syslog("generating new puppet certificate for " + hostname)

		## puppet generate a new cert
		if puppet_version[0] <= 4:
			(rcode, stdout, stderr) = sysexec([app.config['PUPPET_BINARY'], "cert", "--confdir", app.config['PUPPET_CONFDIR'], "generate", hostname], shell=False)
		else:
			(rcode, stdout, stderr) = sysexec([app.config['PUPPETSRV_BINARY'], "ca", "generate", "--config", os.path.join(app.config['PUPPET_CONFDIR'], "puppet.conf"), "--certname", hostname], shell=False)

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
		with open(app.config['PUPPET_SSLDIR'] + "public_keys/" + hostname + ".pem","r") as f:
			data['public_key'] = f.read()
	except Exception as ex:
		syslog.syslog("failed to read generated public key file for " + hostname)
		syslog.syslog(str(ex))
		abort(500)

	try:
		with open(app.config['PUPPET_SSLDIR'] + "ca/signed/" + hostname + ".pem","r") as f:
			data['cert'] = f.read()
	except Exception as ex:
		syslog.syslog("failed to read generated certificate file for " + hostname)
		syslog.syslog(str(ex))
		abort(500)

	try:
		with open(app.config['PUPPET_SSLDIR'] + "private_keys/" + hostname + ".pem","r") as f:
			data['private_key'] = f.read()
	except Exception as ex:
		syslog.syslog("failed to read generated certificate file for " + hostname)
		syslog.syslog(str(ex))
		abort(500)

	## send results back as json
	return jsonify(data)

################################################################################

@app.route('/modules', methods=['GET'])
def modules_list():

	if 'X-Auth-Token' not in request.headers:
		syslog.syslog("modules request failed because X-Auth-Token was missing from the request")
		abort(401)
	if request.headers['X-Auth-Token'] != app.config['AUTH_TOKEN']:
		app.logger.warn('modules request failed because the X-Auth-Token was incorrect')
		abort(401)

	## ask the puppet server for a list of modules
	(rcode, stdout, stderr) = sysexec([app.config['PUPPET_BINARY'], "module", "--modulepath=" + app.config['PUPPET_MODULE_PATH'], "list", "--render-as", "yaml"])	

	if rcode != 0:
		syslog.syslog("puppet module list failed")
		syslog.syslog("stdout: " + str(stdout))
		syslog.syslog("stderr: " + str(stderr))
		abort(500)
	else:
		## Try to validate the YAML
		try:
			# work around the stupid ruby object shit in puppet yaml
			yaml.add_multi_constructor(u"!ruby/object:", construct_ruby_object)
			modules = yaml.load(stdout)
		except yaml.YAMLError as ex:
			syslog.syslog("puppet module list returned invalid YAML")
			syslog.syslog("invalid YAML: " + stdout)
			abort(500)

		r = make_response(yaml.dump(modules))
		r.headers['Content-Type'] = "application/x-yaml"
		return r

################################################################################

@app.route('/environment/create', methods=['POST'])
def environment_create():

	if 'X-Auth-Token' not in request.headers:
		syslog.syslog("environment create request failed because X-Auth-Token was missing from the request")
		abort(401)
	if request.headers['X-Auth-Token'] != app.config['AUTH_TOKEN']:
		app.logger.warn('environment create request failed because the X-Auth-Token was incorrect')
		abort(401)

	if not all(k in request.json for k in ["username", "environment_name"]):
		app.logger.warn('environment create request failed because the request was invalid')
		abort(400)

	base_dir = app.config["PUPPET_ENVIRONMENTS_BASE"]
	if not os.path.isdir(base_dir):
		app.logger.error('environment create request failed because the PUPPET_ENVIRONMENTS_BASE doesn\'t exist')
		abort(500)

	if not ENVIRONMENT_NAME_REGEX.match(request.json.get("environment_name", "")):
		app.logger.warn('environment create request failed because the environment_name is invalid')
		abort(400)

	samba_config_dir = app.config["SAMBA_CONFIG_DIR"]
	if not os.path.isdir(samba_config_dir):
		app.logger.error('environment create request failed because the SAMBA_CONFIG_DIR doesn\'t exist')
		abort(500)

	environment_path = os.path.join(base_dir, request.json["environment_name"])
	os.mkdir(environment_path)
	os.chown(environment_path, PUPPET_UID, PUPPET_GID)
	os.mkdir(os.path.join(environment_path, "hieradata"))
	os.chown(os.path.join(environment_path, "hieradata"), PUPPET_UID, PUPPET_GID)
	os.mkdir(os.path.join(environment_path, "manifests"))
	os.chown(os.path.join(environment_path, "manifests"), PUPPET_UID, PUPPET_GID)
	os.mkdir(os.path.join(environment_path, "modules"))
	os.chown(os.path.join(environment_path, "modules"), PUPPET_UID, PUPPET_GID)

	now = datetime.datetime.now().isoformat()

	# Create environment.conf inside the environment
	with open(os.path.join(environment_path, "environment.conf"), "w") as fp:
		fp.write("""# Cortex Created Puppet Environment
#
# Name: {name}
# Created by: {username}
# Created On: {date}
# See: https://puppet.com/docs/puppet/latest/config_file_environment.html
""".format(name=request.json["environment_name"], username=request.json["username"], date=now))

	os.chown(os.path.join(environment_path, "environment.conf"), PUPPET_UID, PUPPET_GID)

	# Create a samba config
	with open(os.path.join(samba_config_dir, "ctx-env-{}.conf".format(request.json["environment_name"])), "w") as fp:
		fp.write("""# Cortex Created Puppet Environment
#
# Name: {name}
# Created by: {username}
# Created On: {date}
[env-{name}]
path = {path}
force user = puppet
force group = puppet
valid users = +srvadm {username}
browseable = no
writeable = yes
""".format(name=request.json["environment_name"], username=request.json["username"], date=now, path=environment_path))

	(rc, _, _) = sysexec(app.config["SAMBA_BUILD_CMD"], shell=False)
	if rc != 0:
		app.logger.error('environment create request failed because the samba build cmd failed: rc: %s', rc)
		abort(500)


	(rc, _, _) = sysexec(app.config["SAMBA_RESTART_CMD"], shell=False)
	if rc != 0:
		app.logger.error('environment create request failed because the samba restart cmd failed: rc: %s', rc)
		abort(500)

	return jsonify({}), 200

################################################################################

@app.route('/environment/delete', methods=['POST'])
def environment_delete():

	if 'X-Auth-Token' not in request.headers:
		syslog.syslog("environment delete request failed because X-Auth-Token was missing from the request")
		abort(401)
	if request.headers['X-Auth-Token'] != app.config['AUTH_TOKEN']:
		app.logger.warn('environment delete request failed because the X-Auth-Token was incorrect')
		abort(401)

	if not all(k in request.json for k in ["username", "environment_name"]):
		app.logger.warn('environment delete request failed because the request was invalid')
		abort(400)

	base_dir = app.config["PUPPET_ENVIRONMENTS_BASE"]
	if not os.path.isdir(base_dir):
		app.logger.error('environment delete request failed because the PUPPET_ENVIRONMENTS_BASE doesn\'t exist')
		abort(500)

	if not ENVIRONMENT_NAME_REGEX.match(request.json.get("environment_name", "")):
		app.logger.warn('environment delete request failed because the environment_name is invalid')
		abort(400)

	samba_config_dir = app.config["SAMBA_CONFIG_DIR"]
	if not os.path.isdir(samba_config_dir):
		app.logger.error('environment create request failed because the SAMBA_CONFIG_DIR doesn\'t exist')
		abort(500)


	# Sanity check
	environment_path = os.path.join(base_dir, request.json["environment_name"])
	if not request.json["environment_name"] or os.path.realpath(environment_path) == base_dir:
		app.logger.error('environment delete request failed because an invalid path was provided')
		abort(400)

	# Remove environment folder
	if os.path.isdir(environment_path):
		app.logger.info('deleting environment {name} request received from user: {user}'.format(name=environment_path, user=request.json["username"]))
		shutil.rmtree(environment_path)

	# Remove the samba config
	samba_config_file = os.path.join(samba_config_dir, "ctx-env-{}.conf".format(request.json["environment_name"]))
	if os.path.isfile(samba_config_file):
		os.remove(samba_config_file)

	(rc, _, _) = sysexec(app.config["SAMBA_BUILD_CMD"], shell=False)
	if rc != 0:
		app.logger.error('environment create request failed because the samba build cmd failed: rc: %s', rc)
		abort(500)

	(rc, _, _) = sysexec(app.config["SAMBA_RESTART_CMD"], shell=False)
	if rc != 0:
		app.logger.error('environment create request failed because the samba restart cmd failed: rc: %s', rc)
		abort(500)


	return jsonify({}), 200


################################################################################

def get_puppet_version():
	(ret, out, err) = sysexec([app.config['PUPPET_BINARY'], '--version'], shell=False)

	if ret == 0:
		version_string_re = re.compile('(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)')
		version_string = version_string_re.match(out.strip())
		if version_string is not None:
			return (int(version_string.group('major')), int(version_string.group('minor')), int(version_string.group('patch')))
		else:
			raise Exception('Failed to parse Puppet version string')
	else:
		raise Exception('Error running Puppet to get Puppet version')

################################################################################

def construct_ruby_object(loader, suffix, node):
	return loader.construct_yaml_map(node)

################################################################################

@app.before_request
def before_request():
	syslog.openlog("cortex-puppet-bridge")

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
