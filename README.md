# diorite
Authenticated puppet cert signing system

# diorite

__A puppet certificate authenticated signing system replacing autosign__

### What is diorite?

Joing a Puppet agent to a Puppet master is a largely manual process, involving typing commands on the client and then the master, and then the client again. The alternatives from PuppetLabs involve "autosign" (the 'just sign anything' approach, which lacks security of any kind) or the certificate embeddeding system, which essentially uses a pre-shared key embedded in a certificate (forever).

diorite is an alternative system for remote certficiate signing. diorite is a python Flask web app which runs on the puppet master and receives signing requests from clients. It authenticates the requests and then generates and delivers certificates to clients. 

diorite aims to support:

- Username/password authentication (LDAP) over HTTPS. This was inspired by how Windows clients join Active Directory at install time via username/password.
- VMware UUID integration. Virtual machines present their VMware UUID to diorite which checks with VMware to see if the UUID is valid and the presented hostname matches, if it does then a certificate is generated for that hostname and delivered to the client.
- Pre-shared key support - the client presents a pre-shared key and if its correct a certificate is generated and delivered to the client.

diorite is the sister project of [bonemeal](https://github.com/southampton/bonemeal) - a client installation program that relies on diorite.
