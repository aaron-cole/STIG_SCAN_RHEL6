#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The actions taken by system administrators should be audited to keep a record of what was executed on the system, as well as, for accountability purposes.

#STIG Identification
GrpID="V-217979"
GrpTitle="SRG-OS-000064"
RuleID="SV-217979r505923_rule"
STIGID="RHEL-06-000201"
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

if auditctl -l | awk '/^-w \/etc\/sudoers -p wa/' >> $Results; then
 echo "Pass" >> $Results
else 
 echo "Audit Rule not found" >> $Results
 echo "Fail" >> $Results
fi

