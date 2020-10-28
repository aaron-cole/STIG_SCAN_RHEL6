#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Automatically rotating logs (by setting this to "rotate") minimizes the chances of the system unexpectedly running out of disk space by being overwhelmed with log data. However, for systems that must never discard log data, or which use external processes to transfer it and reclaim space, "keep_logs" can be employed.

#STIG Identification
GrpID="V-217949"
GrpTitle="SRG-OS-000480"
RuleID="SV-217949r505923_rule"
STIGID="RHEL-06-000161"
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

if grep "^max_log_file_action" /etc/audit/auditd.conf| egrep -vi "suspend|ignore|syslog|keep_logs" >> $Results; then 
 echo "Pass" >> $Results
else
 grep "^max_log_file_action" /etc/audit/auditd.conf >> $Results
 echo "Fail" >> $Results
fi
