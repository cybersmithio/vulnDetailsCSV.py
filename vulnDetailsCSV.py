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
import getpass
		
################################################################
# Description: Downloads the report based on the report number
#
#    Earlier versions of this download function simply dumped
#    the report file from the variable containing the HTTP 
#    response.  Doing this locked up the CPU.  So the current
#    version writes the report file in chucks and pauses for 
#    one second in between chunks.  The result is large report
#    files will take a couple of minutes to write but the CPU
#    will not be nearly as impacted.
################################################################
# Input:
#        scsm = the SecurityCenter Security Manager session object
#        reportnumber = the ID number of the report to download
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
def DownloadReport(scsm,reportnumber):
	#Attempt to download report
	reporturl='report/'+str(reportnumber)+'/download'
	if DEBUG:
		print "Report is ready to download"
		print "Report URL:",reporturl
	represp=scsm.post(reporturl,json={'id': int(reportnumber)})
	if DEBUG:
		print "Report response",represp
		print "Report response text",represp.text

		
	#Since writing large CSV files in one go seems to spike CPU usage,
	# just write one character at a time to allow the CPU an opportunity
	# to switch.
	print time.ctime()," Writing report to output.csv"
	f=open('output.csv','wb')
	i=0
	l=len(represp.content)
	print "Total bytes to write:",l
	x=10000000
	while i < l:
		f.write(represp.content[i:(i+x)])
		i=i+x
		time.sleep(1)
	f.close

	return(True)

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
def GenerateReport(scsm):
	#First upload the XML file, then tell SC to import it.
	DEBUG=False

	print time.ctime()," Sending request for a report"

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
		print "Report successfully submitted.  Report ID is",respdata['response']['reportResultID']
		
		#Get the status of the report:
		reportstatus="Queued"
		starttime=int(time.time())
		#Check the report status every 10 seconds at the start.  If it runs longer than 2 minutes, then check every 60 seconds.
		checkinterval=10
		while reportstatus != "Completed":
			sys.stdout.write('Waiting for report to finish. Total elapsed time in seconds: '+str( int(time.time())-starttime )+' Status: '+reportstatus+'                        \r')
			sys.stdout.flush()

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

			if represpdata['error_code'] != 0:
				print "\n\nResponse error code/error message",represpdata['error_code'],"/",represpdata['error_msg']
				print "There was an error reported when trying to get the status of the report"
				return(False)

			#If the status changed, start a new line to help show the progress of the report.
			try:
				if represpdata['response']['status'] != reportstatus:
					print ""
			except:
				return(False)
			reportstatus=represpdata['response']['status']
			

			#If this is a long running report, then switch to checking every minute
			if int(time.time())-starttime >= 120:
				checkinterval=60
			time.sleep(checkinterval)
		print "\nReport has completed, attempting download"
		DownloadReport(scsm,respdata['response']['reportResultID'])

		print "Report successfully downloaded into output.csv"
		return(True)
			

	#There was a problem, so return a False value
	print "Error submitting report"
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
	password=getpass.getpass("Password:")


print "Connecting to",schost,"as",username,"to download vulnerability details"

#Create a session as the user
conncount=0
while conncount < 3:
	try:
		scsm=SecurityCenter5(schost)
		break
	except:
		conncount+=1
		print "Problem connecting to SecurityCenter. Attempt #"+str(conncount)
		print "Retrying in 15 seconds"
		time.sleep(15)

if conncount >= 3:
	exit(-1)
		
print "TCP Connection to SecurityCenter established. Attempting login."
try:
	scsm.login(username,password)
except:
	print "Login failed, invalid credentials"
	exit(-1)
print "Logged in as "+str(username)+" to SecurityCenter at "+str(schost)

#Upload demo dashboards
if GenerateReport(scsm):
	print "vulnDetailsCSV.py successfully completed"
	exit(0)
else:
	print "Unable to download report"
	exit(-1)

