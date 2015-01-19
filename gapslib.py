#!/usr/bin/env python

import binascii
import ConfigParser
import gdata.apps.multidomain.client
import hashlib
import imp
import quopri
import re
import syslog
import sys
import textwrap


try:
    imp.find_module('samba')
except ImportError:
    # Add a specific import for the Python Samba packages
    sys.path.append("/usr/local/samba/lib/python2.7/site-packages/")

from samba.credentials import Credentials
from samba.auth import system_session
from samba.dcerpc import drsblobs
from samba.ndr import ndr_unpack
from samba.samdb import SamDB


### Configure your settings in secrets.cfg
config = ConfigParser.ConfigParser()
config.read("secrets.cfg")

gaDomain = config.get('google', 'domain')
gaEmail = config.get('google', 'email')
gaPassword = config.get('google', 'password')
replaceDomain = config.get('google', 'replaceDomain')

sambaPrivate = config.get('samba', 'sambaPrivate')
sambaPath = config.get('samba', 'sambaPath')
adBase = config.get('samba', 'adBase')


## Open connection to Syslog ##
syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL3)

## Cached SHA 1 Passwords ##
passwords = {}

## Connect to Google ##
client = gdata.apps.multidomain.client.MultiDomainProvisioningClient(domain=gaDomain)
client.ssl = True
client.ClientLogin(email=gaEmail, password=gaPassword, source='apps')

def esc(s):
    return quopri.encodestring(s, quotetabs=True)

def print_entry(dn, user, mail, pwd):
    print('%s\t%s\t%s\t%s' % tuple([esc(p) for p in [dn, user, mail, pwd]]))

def update_password(mail, pwd):
    pwd = pwd.encode('ascii', 'ignore')
    password = hashlib.sha1(pwd).hexdigest()

    if replaceDomain:
      mail = re.search("([\w.-]+)@", mail).group() + gaDomain

    if mail in passwords:
        if passwords[mail] == password:
            return False
    try:
        user = client.RetrieveUser(mail)
    except:
        syslog.syslog(syslog.LOG_WARNING, '[WARNING] Account %s not found' % mail)
        return False

    user.password = password
    user.hash_function="SHA-1"
    try:
        client.UpdateUser(mail, user)
        syslog.syslog(syslog.LOG_WARNING, '[NOTICE] Updated password for %s' % mail)
        passwords[mail] = password
    except:
        syslog.syslog(syslog.LOG_WARNING, '[ERROR] Could not update password for %s ' % mail)

def run():
    creds = Credentials()
    samdb = SamDB(url=(sambaPrivate + "/sam.ldb.d/" + sambaPath + ".ldb"), session_info=system_session(), credentials=creds.guess())
    res = samdb.search(base=adBase, expression="(objectClass=user)", attrs=["supplementalCredentials", "sAMAccountName", "pwdLastSet", "mail"])

    for r in res:
         if not "supplementalCredentials" in r:
             sys.stderr.write("%s: no supplementalCredentials\n" % str(r["dn"]))
             continue
         scb = ndr_unpack(drsblobs.supplementalCredentialsBlob, str(r["supplementalCredentials"]))
         for p in scb.sub.packages:
             if p.name == "Primary:CLEARTEXT":
                 update_password(str(r["mail"]), binascii.unhexlify(p.data).decode("utf16"))

