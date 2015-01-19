#!/usr/bin/env python2

# Unfortunately, the Google API doesn't support Py3 yet :(


import binascii

try:
    import ConfigParser as configparser
except ImportError:
    import configparser

import httplib2
import imp
import os
import pickle
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

_CONFIG = configparser.ConfigParser()
_CONFIG.read("secrets.cfg")

NOTIFY_USERS = _CONFIG.get('general', 'notifyUsers')

GA_DOMAIN = _CONFIG.get('google', 'domain')
SERVICE_ACCOUNT = _CONFIG.get('google', 'serviceAccount')
SERVICE_ACCOUNT_KEY = _CONFIG.get('google', 'serviceAccountKey')
ADMIN_TO_IMPERSONATE = _CONFIG.get('google', 'adminToImpersonate')
GA_BLACKLISTED_USERS = _CONFIG.get('google', 'blacklistedUsers')
REPLACE_DOMAIN = _CONFIG.get('google', 'replaceDomain')

SAMBA_PRIVATE = _CONFIG.get('samba', 'sambaPrivate')
SAMBA_PATH = _CONFIG.get('samba', 'sambaPath')
AD_BASE = _CONFIG.get('samba', 'adBase')
SAMBA_BLACKLISTED_USERS = _CONFIG.get('samba', 'blacklistedUsers')

##########################################


# Open connection to syslog
syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL3)


def send_email_to_admin(message, iserror=False):
    """
    Send an e-mail to an administrator (defined in secrets.cfg).

    Derived: https://stackoverflow.com/questions/2020476/how-do-i-send-a-mail-via-mailx-subprcoess
    """
    from_user = "root@example.com"
    subject = "Samba password change"
    if iserror:
        subject = "ERROR in Samba password change!"
    full_message = """\
    From: %s
    To: %s
    Subject: %s
    
    %s
    """ % (from_user, ", ".join(TO), subkect, message)

    server = smtplib.SMTP("localhost")
    server.set_debuglevel(3)
    server.sendmail(from_user, NOTIFY_USERS, full_message)
    server.quit()


def update_password(email, password):
    """
    Update a Google Apps password.
    """
    print("Preparing Google password change, given e-mail: %s" % (email))
    assert(email.endswith(GA_DOMAIN))
    assert(email not in GA_BLACKLISTED_USERS)

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

    if REPLACE_DOMAIN:
        print("Replacing domain. This function is untested (!!)")
        email = re.search("([\w.-]+)@", email).group() + GA_DOMAIN

    print("Updating password at Google Apps for %s" % (email))
    return False
    updated = service.users().update(userKey=email, body={"password": password}).execute(http=http)
    pprint.pprint(updated)

    # syslog.syslog(syslog.LOG_WARNING, '[NOTICE] Updated password for %s' % email)


def check_for_changed_passwords():
    """
    Check for any Samba users with recently changed passwords.

    We compare the AD parameter "pwdLastSet" with one stored in our pickle .cache.pkl file.

    Note: We use the username@GA_DOMAIN, instead of the AD "mail" parameter.
    
    You could easily extend this to use the "mail" field instead -- please send a pull request if you do.
    """

    try:
        with open('.cache.pkl', 'rb') as cachefile:
            pwd_last_set = pickle.load(cachefile)
    except IOError:
        print("** No cache found. Are we running for the first time?\n")
        pwd_last_set = {}  # {'user@domain.com': pwdLastSet}

    print("Connecting to Samba")
    creds = Credentials()
    samdb = SamDB(url=(SAMBA_PRIVATE + "/sam.ldb.d/" + SAMBA_PATH + ".ldb"), session_info=system_session(), credentials=creds.guess())
    res = samdb.search(base=AD_BASE, expression="(objectClass=user)", attrs=["supplementalCredentials", "sAMAccountName", "pwdLastSet", "mail"])

    print("Looping over users in domain.\n")
    for r in res:
        username = str(r["sAMAccountName"])
        # print("User: %s" % (username))

        if str(r["sAMAccountName"]) in SAMBA_BLACKLISTED_USERS:
            print("Skipped user due to blacklist: %s" % (username))
            continue

        if not "supplementalCredentials" in r:
            sys.stderr.write("%s: no supplementalCredentials\n" % str(r["dn"]))
            continue

        saw_cleartext = False
        scb = ndr_unpack(drsblobs.supplementalCredentialsBlob, str(r["supplementalCredentials"]))
        user_email = "%s@%s" % (str(r["sAMAccountName"]), GA_DOMAIN)

        for p in scb.sub.packages:
            if p.name == "Primary:CLEARTEXT":
                saw_cleartext = True
                last_set = int(str(r["pwdLastSet"]))

                if last_set == "Null":  # TODO: See actual value
                    # User forced to change pass at next logon.
                    break

                if user_email in pwd_last_set:  # Existing user
                    if pwd_last_set[user_email] == last_set:
                        # Password has not been changed.
                        # print("Unchanged password: %s" % (username))
                        break
                else:
                    print("New user found: %s" % (username))

                update_password(user_email, binascii.unhexlify(p.data).decode("utf16"))
                pwd_last_set[user_email] = last_set
                    
        
        if not saw_cleartext:
            # syslog.syslog(syslog.LOG_WARNING, '[NOTICE] test lolUpdated password for %s' % user_email)
            print("No cleartext found for: %s" % (username))

    with open('.cache.pkl', 'wb') as cache:
        pickle.dump(pwd_last_set, cache)


if __name__ == "__main__":
    check_for_changed_passwords()
