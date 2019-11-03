#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.

#STIG Identification
GrpID="V-38556"
GrpTitle="SRG-OS-000064"
RuleID="SV-50357r4_rule"
STIGID="RHEL-06-000190"
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

 if ! auditctl -l | awk '/^-a always,exit -F arch=b32 -S .*[^-F key=]fremovexattr[, ].*-F auid>=500 -F auid!=-1/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b64 -S .*[^-F key=]fremovexattr[, ].*-F auid>=500 -F auid!=-1/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b32 -S .*[^-F key=]fremovexattr[, ].*-F auid=0/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b64 -S .*[^-F key=]fremovexattr[, ].*-F auid=0/' >> $Results; then
  ((scorecheck+=1))
 fi
		
if [ "$scorecheck" != 0 ]; then
 echo "Audit Rules not found" >> $Results
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
