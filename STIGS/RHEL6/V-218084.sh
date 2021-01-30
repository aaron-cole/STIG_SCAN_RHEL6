#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If users can write to audit logs, audit trails can be modified or destroyed.

#STIG Identification
GrpID="V-218084"
GrpTitle="SRG-OS-000058"
RuleID="SV-218084r603264_rule"
STIGID="RHEL-06-000383"
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

grep "log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %a >> $Results

if [ "$(grep "log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %a)" == "600" ] || [ "$(grep "log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %a)" == "640" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
