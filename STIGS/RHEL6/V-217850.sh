#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Notifying administrators of an impending disk space problem may allow them to take corrective action prior to any disruption.

#STIG Identification
GrpID="V-217850"
GrpTitle="SRG-OS-000343"
RuleID="SV-217850r505923_rule"
STIGID="RHEL-06-000005"
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

if grep "^space_left_action" /etc/audit/auditd.conf | egrep -vi "suspend|ignore|exec|single|halt|syslog|rotate" >> $Results; then
 echo "Pass" >> $Results
else 
 grep "^space_left_action" /etc/audit/auditd.conf >> $Results
 echo "Fail" >> $Results
fi
