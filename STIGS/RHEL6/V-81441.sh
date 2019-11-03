#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.

#STIG Identification
GrpID="V-81441"
GrpTitle="SRG-OS-000062"
RuleID="SV-96155r2_rule"
STIGID="RHEL-06-000166"
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

if [ "$(uname -i)" == "x86_64" ]; then
 rules="b64 b32"
else
 rules="b32"
fi

for rule in $rules; do
 if ! auditctl -l | awk '/^-a always,exit -F arch=$rule -S .*[^-F key=]adjtimex[, ]/' >> $Results; then
  ((scorecheck+=1))
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Audit Rules not found" >> $Results
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
