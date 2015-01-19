#!/usr/bin/env python

# https://developers.google.com/gmail/markup/actions/verifying-bearer-tokens

import binascii
import ConfigParser
import hashlib
import httplib2
import imp
import os
import pickle
import quopri
import re
import smtplib
import syslog
import sys

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

_CONFIG = ConfigParser.ConfigParser()
_CONFIG.read("secrets.cfg")

NOTIFY_USER = _CONFIG.get('general', 'notifyUser')

GA_DOMAIN = _CONFIG.get('google', 'domain')
SERVICE_ACCOUNT = _CONFIG.get('google', 'serviceAccount')
SERVICE_ACCOUNT_KEY = _CONFIG.get('google', 'serviceAccountKey')
ADMIN_TO_IMPERSONATE = _CONFIG.get('google', 'adminToImpersonate')
REPLACE_DOMAIN = _CONFIG.get('google', 'replaceDomain')

SAMBA_PRIVATE = _CONFIG.get('samba', 'sambaPrivate')
SAMBA_PATH = _CONFIG.get('samba', 'sambaPath')
AD_BASE = _CONFIG.get('samba', 'adBase')

##########################################


## Open connection to Syslog ##
syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL3)



def esc(s):
    return quopri.encodestring(s, quotetabs=True)

def print_entry(dn, user, mail, pwd):
    print('%s\t%s\t%s\t%s' % tuple([esc(p) for p in [dn, user, mail, pwd]]))

def send_email_to_admin(message):
    """
    Send an e-mail to an administrator (defined in secrets.cfg).
    """
    # NOTIFY_USER
    pass

def update_password(email, pwd):
    """
    Update a Google Apps password.
    """

    # Grab the service account .p12 private key
    with open('secret.p12', 'rb') as f:
        service_secret_key = f.read()  # Google's fixed password for all keys is "notasecret"
    
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

    if REPLACE_DOMAIN:
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


def check_for_changed_passwords():
    """
    Check for any Samba users with recently changed passwords.

    We compare the AD parameter "pwdLastSet" with one stored in our pickle .cache.pkl file.
    """
    creds = Credentials()
    samdb = SamDB(url=(SAMBA_PRIVATE + "/sam.ldb.d/" + SAMBA_PATH + ".ldb"), session_info=system_session(), credentials=creds.guess())
    res = samdb.search(base=AD_BASE, expression="(objectClass=user)", attrs=["supplementalCredentials", "sAMAccountName", "pwdLastSet", "mail"])

    for r in res:
         if not "supplementalCredentials" in r:
             sys.stderr.write("%s: no supplementalCredentials\n" % str(r["dn"]))
             continue
         scb = ndr_unpack(drsblobs.supplementalCredentialsBlob, str(r["supplementalCredentials"]))
         for p in scb.sub.packages:
             if p.name == "Primary:CLEARTEXT":
                 update_password(str(r["mail"]), binascii.unhexlify(p.data).decode("utf16"))


if __name__ == "__main__":
    check_for_changed_passwords()
