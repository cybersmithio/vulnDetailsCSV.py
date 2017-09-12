# Overview
A Python script to download the vulnerability details in a CSV format from SecurityCenter 5.x.

Requires the pySecurityCenter project at https://github.com/SteveMcGrath/pySecurityCenter

# How To Install
To install pySecurityCenter, you can use either pip or easy_install to install from the cheeseshop:

  pip install pysecuritycenter

  easy_install pysecuritycenter

# Running
The script requires an IP or hostname and a set of user credentials with privileges to view vulnerability data.

# How To Run Without Prompts

The script will prompt for inputs if it needs information.  Everything can be supplied by environment variables.  The variables include SCHOST, SCUSERNAME, and SCPASSWORD.

For example:

SCHOST=192.168.1.1; export SCHOST

SCUSERNAME=jamessmith;export SCUSERNAME

SCPASSWORD=************ ; export SCPASSWORD

./vulnDetailsCSV.py
