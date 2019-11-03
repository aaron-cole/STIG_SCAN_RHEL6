#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The system

#STIG Identification
GrpID="V-38541"
GrpTitle="SRG-OS-999999"
RuleID="SV-50342r2_rule"
STIGID="RHEL-06-000183"
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

if auditctl -l | awk '/^-w \/etc\/selinux\/ -p wa/' >> $Results; then
 echo "Pass" >> $Results
else
 echo "Audit Rule not found" >> $Results 
 echo "Fail" >> $Results
fi