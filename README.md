Sync Samba4 AD Passwords to Google Apps
===========


Reads from your Samba4 AD and updates changes password to Google Apps in SHA1 format.
Note that this solution requires you to run:

samba-tool domain passwordsettings set --store-plaintext=on

Also you will have to use "Store passwords using reversible encryption" for each users. This can be enabled with MS Active Directory snap in tool from Windows.


Getting Credentials
===========

1. 
2.
3.
4.


Installation
===========

0. Follow the "Getting Credentials" instructions above
1. Install requirements: pip install -r requirements.txt
2. Complete the rest of secrets.cfg (you started in "Getting Credentials")
3. Modify the /usr/local/samba/private/sam.ldb.d/ permissions to be readable by this script


Security Warnings
===========

1. Do NOT run this 
