#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If non-privileged users can write to audit logs, audit trails can be modified or destroyed.

#STIG Identification
GrpID="V-38445"
GrpTitle="SRG-OS-000057"
RuleID="SV-50245r2_rule"
STIGID="RHEL-06-000522"
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

grep "^log_file" /etc/audit/auditd.conf | sed s/^[^\/]*//|xargs stat -c %G >> $Results

if [ "$(grep "^log_file" /etc/audit/auditd.conf | sed s/^[^\/]*//|xargs stat -c %G)" == "root" ]; then 
 echo "Pass" >> $Results
else
 echo "Fail" >> $Results
fi
