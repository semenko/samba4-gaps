#!/usr/bin/env python

# https://developers.google.com/gmail/markup/actions/verifying-bearer-tokens

import binascii
import ConfigParser
import hashlib
import httplib2
import imp
import inspect
import os
import quopri
import re
import smtplib
import syslog
import sys
import textwrap

# Google Imports
from apiclient.discovery import build
from oauth2client.client import SignedJwtAssertionCredentials

# Samba Imports
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


##########################################
### Configure your settings in secrets.cfg
##########################################

assert(os.path.isfile('secret.p12'))

config = ConfigParser.ConfigParser()
config.read("secrets.cfg")

notifyUser = config.get('general', 'notifyUser')

GA_DOMAIN = config.get('google', 'domain')
SERVICE_ACCOUNT = config.get('google', 'serviceAccount')
SERVICE_ACCOUNT_KEY = config.get('google', 'serviceAccountKey')
ADMIN_TO_IMPERSONATE = config.get('google', 'adminToImpersonate')
replaceDomain = config.get('google', 'replaceDomain')

sambaPrivate = config.get('samba', 'sambaPrivate')
sambaPath = config.get('samba', 'sambaPath')
adBase = config.get('samba', 'adBase')

##########################################


## Open connection to Syslog ##
syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL3)

## Cached SHA 1 Passwords ##
passwords = {}

def esc(s):
    return quopri.encodestring(s, quotetabs=True)

def print_entry(dn, user, mail, pwd):
    print('%s\t%s\t%s\t%s' % tuple([esc(p) for p in [dn, user, mail, pwd]]))

def send_email_to_admin(message):
    """
    Send an e-mail to an administrator (defined in secrets.cfg).
    """
    pass

def update_password(email, pwd):
    """
    Update a Google Apps password.
    """

    f = file('secret.p12', 'rb') # notasecret
    key = f.read()
    f.close()
    
    credentials = SignedJwtAssertionCredentials(
        SERVICE_ACCOUNT,
        SERVICE_ACCOUNT_KEY,
        sub=ADMIN_TO_IMPERSONATE,
        scope=['https://www.googleapis.com/auth/admin.directory.user']
    )
    
    http = httplib2.Http()
    http = credentials.authorize(http)
    
    service = build("admin", "directory_v1", http)
    updated = service.users().update(userKey=email, body={"password": pwd}).execute(http=http)
    pprint.pprint(updated)



    pwd = pwd.encode('ascii', 'ignore')
    password = hashlib.sha1(pwd).hexdigest()

    if replaceDomain:
      email = re.search("([\w.-]+)@", email).group() + GA_DOMAIN

    if email in passwords:
        if passwords[email] == password:
            return False
    try:
        user = client.RetrieveUser(email)
    except:
        syslog.syslog(syslog.LOG_WARNING, '[WARNING] Account %s not found' % email)
        return False

    user.password = password
    user.hash_function="SHA-1"
    try:
        client.UpdateUser(email, user)
        syslog.syslog(syslog.LOG_WARNING, '[NOTICE] Updated password for %s' % email)
        passwords[email] = password
    except:
        syslog.syslog(syslog.LOG_WARNING, '[ERROR] Could not update password for %s ' % email)


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

