#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Taking appropriate action in case of disk errors will minimize the possibility of losing audit records.

#STIG Identification
GrpID="V-218094"
GrpTitle="SRG-OS-000047"
RuleID="SV-218094r603264_rule"
STIGID="RHEL-06-000511"
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

if grep "^disk_error_action" /etc/audit/auditd.conf | egrep -vi "suspend|ignore" >> $Results; then
 echo "Pass" >> $Results
else
 grep "^disk_error_action" /etc/audit/auditd.conf >> $Results
 echo "Fail" >> $Results 
fi
