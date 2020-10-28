#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If users can delete audit logs, audit trails can be modified or destroyed.

#STIG Identification
GrpID="V-218086"
GrpTitle="SRG-OS-000059"
RuleID="SV-218086r505923_rule"
STIGID="RHEL-06-000385"
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

grep "^log_file" /etc/audit/auditd.conf | cut -f 2 -d"=" | xargs stat -c %a >> $Results

if [ $(grep "^log_file" /etc/audit/auditd.conf | cut -f 2 -d"=" | xargs stat -c %a) -le 755 ]; then
 echo "Pass" >> $Results
else
 echo "Fail" >> $Results 
fi
