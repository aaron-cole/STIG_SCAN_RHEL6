#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Administrators should be made aware of an inability to record audit records. If a separate partition or logical volume of adequate size is used, running low on space for audit records should never occur. 

#STIG Identification
GrpID="V-217950"
GrpTitle="SRG-OS-000343"
RuleID="SV-217950r505923_rule"
STIGID="RHEL-06-000163"
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

if grep "^admin_space_left_action" /etc/audit/auditd.conf | egrep -vi "ignore|syslog|rotate|email|exec" >> $Results; then 
 echo "Pass" >> $Results
else
 grep "^admin_space_left_action" /etc/audit/auditd.conf >> $Results 
 echo "Fail" >> $Results
fi
