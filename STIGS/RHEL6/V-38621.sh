#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Synchronizing with an NTP server makes it possible to collate system logs from multiple sources or correlate computer events with real time events. Using a trusted NTP server provided by your organization is recommended.

#STIG Identification
GrpID="V-38621"
GrpTitle="SRG-OS-000056"
RuleID="SV-50422r1_rule"
STIGID="RHEL-06-000248"
Results="./Results/$GrpID"

#Remove File if already there
[ -e $Results ] && rm -rf $Results

#Setup Results File
echo $GrpID >> $Results
echo $GrpTitle >> $Results
echo $RuleID >> $Results
echo $STIGID >> $Results
##END of Automatic Items##

###Check###

if awk '/^server .*/' /etc/ntp.conf >> $Results; then 
 echo "Pass" >> $Results
else 
 echo "Time Servers are not defined" >> $Results
 echo "Fail" >> $Results
fi
