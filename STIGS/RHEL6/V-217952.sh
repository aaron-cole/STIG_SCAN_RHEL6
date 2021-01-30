#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.

#STIG Identification
GrpID="V-217952"
GrpTitle="SRG-OS-000062"
RuleID="SV-217952r603264_rule"
STIGID="RHEL-06-000167"
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
scorecheck=0

if ! auditctl -l | awk '/^-a always,exit -F arch=b32 -S .*[^-F key=]settimeofday[, ]/' >> $Results; then
 ((scorecheck+=1))
fi
if ! auditctl -l | awk '/^-a always,exit -F arch=b64 -S .*[^-F key=]settimeofday[, ]/' >> $Results; then
 ((scorecheck+=1))
fi

if [ "$scorecheck" != 0 ]; then
 echo "Audit Rules not found" >> $Results
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
