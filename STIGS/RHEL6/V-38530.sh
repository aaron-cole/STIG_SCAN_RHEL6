#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.

#STIG Identification
GrpID="V-38530"
GrpTitle="SRG-OS-000062"
RuleID="SV-50331r2_rule"
STIGID="RHEL-06-000173"
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

if ! auditctl -l | awk '/^-w \/etc\/localtime -p wa/' >> $Results; then
 echo "Audit Rule not found" >> $Results
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi