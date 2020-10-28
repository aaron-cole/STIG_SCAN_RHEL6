#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.

#STIG Identification
GrpID="V-217953"
GrpTitle="SRG-OS-000062"
RuleID="SV-217953r505923_rule"
STIGID="RHEL-06-000169"
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

if uname -i | grep 64 >> $Results; then 
 echo "NA on 64 bit system" >> $Results
 echo "NA" >> $Results
else  
 if auditctl -l | awk '/^-a always,exit -F arch=b32 -S .*[^-F key=]stime[, ]/' >> $Results; then
  echo "Pass" >> $Results 
 else
  echo "Audit Rule not found" >> $Results 
  echo "Fail" >> $Results
 fi
fi
