#!/usr/bin/python
#
# This script triggers a CSV report to launch through SecurityCenter.
# It is a vulnerability detail list in CSV format.
#
# The script will either prompt for information, read from the command line
# or read from environment variables.  It will not read passwords
# from the command line.
#
# Version 1.0
#
# Roadmap
#   
# Sample usage:
#
# SCHOST=192.168.1.1; export SCHOST
# SCUSERNAME=jamessmith;export SCUSERNAME
# SCPASSWORD=***********;export SCPASSWORD
# ./vulnDetailsCSV.py
#


import sys
import os
import re
import string
import json
from datetime import datetime,date, time
import time
import requests
from securitycenter import SecurityCenter5
		
		
################################################################
# Description: Launches report
################################################################
# Input:
#        scsm = the SecurityCenter Security Manager session object
#
################################################################
# Output:
#        True = Successfully completed operation
#        False = Did not successfully complete the operation
################################################################
# To do:
#
#
################################################################
def DownloadReport(scsm):
	#First upload the XML file, then tell SC to import it.
	DEBUG=False
	if DEBUG:
		print "Launching report"

	resp=scsm.post('reportDefinition',json={
		'name':'Vulnerability detail list','description':'','context':'','status':-1,'createdTime':0,'modifiedTime':0,'groups':[],'schedule':{'start':'TZID=:Invalid dateInvalid date','repeatRule':'FREQ=NOW;INTERVAL=','type':'now'},'type':'csv','definition':{'dataPoints':2147483647,'columns':[{'name':'pluginID'},{'name':'pluginName'},{'name':'familyID'},{'name':'severity'},{'name':'ip'},{'name':'protocol'},{'name':'port'},{'name':'exploitAvailable'},{'name':'repositoryID'},{'name':'macAddress'},{'name':'dnsName'},{'name':'netbiosName'},{'name':'pluginText'},{'name':'synopsis'},{'name':'description'},{'name':'solution'},{'name':'seeAlso'},{'name':'riskFactor'},{'name':'stigSeverity'},{'name':'baseScore'},{'name':'temporalScore'},{'name':'cvssVector'},{'name':'cpe'},{'name':'cve'},{'name':'bid'},{'name':'xref'},{'name':'firstSeen'},{'name':'lastSeen'},{'name':'vulnPubDate'},{'name':'patchPubDate'},{'name':'pluginPubDate'},{'name':'pluginModDate'},{'name':'exploitEase'},{'name':'exploitFrameworks'},{'name':'checkType'},{'name':'version'}],'dataSource':{'query':{'name':'','description':'','context':'','status':-1,'createdTime':0,'modifiedTime':0,'group':{'id':0,'name':'Administrator'},'groups':[],'type':'vuln','tool':'vulndetails','sourceType':'cumulative','filters':[],'vulnTool':'vulndetails'},'sortColumn':'','querySourceID':'','querySourceView':'all','querySourceType':'cumulative'}},'styleFamily':{'id':5,'name':'Plain, Letter','description':'','context':''},'pubSites':[],'shareUsers':[],'emailUsers':[],'emailTargets':'','emailTargetType':'1'})


	if DEBUG:
		print resp
		print resp.text
	respdata=json.loads(resp.text)
	if DEBUG:
		print "\n\nResponse error code/error message",respdata['error_code'],"/",respdata['error_msg']
	if respdata['error_code'] == 0:
		#Get the report ID:
		if DEBUG:
			print "Report submitted.  Report ID is",respdata['response']['reportResultID']
		
		#Get the status of the report:
		reportstatus="Queued"
		while reportstatus != "Completed":
			reporturl='report/'+str(respdata['response']['reportResultID'])
			if DEBUG:
				print "Report URL:",reporturl
			represp=scsm.get(reporturl)
			if DEBUG:
				print "Report response",represp
				print "Report response text",represp.text
			represpdata=json.loads(represp.text)
			if DEBUG:
				print "\n\nResponse error code/error message",represpdata['error_code'],"/",represpdata['error_msg']
			reportstatus=represpdata['response']['status']
			time.sleep(1)
		

		#Attempt to download report
		reporturl='report/'+str(respdata['response']['reportResultID'])+'/download'
		if DEBUG:
			print "Report is ready to download"
			print "Report URL:",reporturl
		represp=scsm.post(reporturl)
		if DEBUG:
			print "Report response",represp
			print "Report response text",represp.text
		if DEBUG:
			print "\n\nResponse error code/error message",represpdata['error_code'],"/",represpdata['error_msg']
		f=open('output.csv','w')
		f.write(represp.text)
		f.close()
		return(True)

	#There was a problem, so return a False value
	return(False)


################################################################
# Start of program 
################################################################
#Set debugging on or off
DEBUG=False

#Pull as much information from the environment variables
# as possible, and where missing then initialize the variables.
if os.getenv('SCHOST') is None:
	schost=""
else:
	schost=os.getenv('SCHOST')
	if DEBUG:
		print "Found SCHOST variable:",schost

if os.getenv('SCUSERNAME') is None:
	username=""
else:
	username=os.getenv('SCUSERNAME')

if os.getenv('SCPASSWORD') is None:
	password=""
else:
	password=os.getenv('SCPASSWORD')

if DEBUG:
	print "Connecting to",schost,"as",username,"to download vulnerability details"

#Pull information from command line.  If nothing there,
# and there was nothing in the environment variables, then ask user.
if len(sys.argv) > 1:
	schost=sys.argv[1]
else:
	if schost == "":
		schost=raw_input("SC Host:")

if len(sys.argv) > 2:
	username=sys.argv[2]
else:
	if username == "":
		username=raw_input("Username:")

if password == "":
	password=raw_input("Password:")


print "Connecting to",schost,"as",username,"to download vulnerability details"

#Create a session as the user
scsm=SecurityCenter5(schost)
scsm.login(username,password)
if DEBUG:
	print "Logged in as "+str(username)+" to SecurityCenter at "+str(schost)

#Upload demo dashboards
if DownloadReport(scsm):
	print "Report downloaded"
	exit(0)
else:
	print "Unable to download report"
	exit(-1)

