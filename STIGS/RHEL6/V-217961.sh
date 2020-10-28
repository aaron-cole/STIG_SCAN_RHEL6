#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The system's mandatory access policy (SELinux) should not be arbitrarily changed by anything other than administrator action. All changes to MAC policy should be audited.

#STIG Identification
GrpID="V-217961"
GrpTitle="SRG-OS-000480"
RuleID="SV-217961r505923_rule"
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
