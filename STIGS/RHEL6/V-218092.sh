#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The auditd service does not include the ability to send audit records to a centralized server for management directly.  It does, however, include an audit event multiplexor plugin (audispd) to pass audit records to the local syslog server.

#STIG Identification
GrpID="V-218092"
GrpTitle="SRG-OS-000342"
RuleID="SV-218092r603264_rule"
STIGID="RHEL-06-000509"
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

if grep active /etc/audisp/plugins.d/syslog.conf | grep -v "#" | grep yes >> $Results; then
 echo "Pass" >> $Results
else 
 grep active /etc/audisp/plugins.d/syslog.conf | grep -v "#" >> $Results
 echo "Fail" >> $Results
fi
