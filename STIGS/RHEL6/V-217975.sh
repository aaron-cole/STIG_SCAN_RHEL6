#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Unsuccessful attempts to access files could be an indicator of malicious activity on a system. Auditing these events could serve as evidence of potential system compromise.

#STIG Identification
GrpID="V-217975"
GrpTitle="SRG-OS-000064"
RuleID="SV-217975r505923_rule"
STIGID="RHEL-06-000197"
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
modules="creat open openat truncate ftruncate"

for module in $modules; do
echo "$module Rules" >> $Results
 if ! auditctl -l | awk '/^-a always,exit -F arch=b32 -S.*[ ,]'"$module"'[, ].*-F exit=-EACCES -F auid>=500 -F auid!=-1/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b64 -S.*[ ,]'"$module"'[, ].*-F exit=-EACCES -F auid>=500 -F auid!=-1/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b32 -S.*[ ,]'"$module"'[, ].*-F exit=-EACCES -F auid=0/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b64 -S.*[ ,]'"$module"'[, ].*-F exit=-EACCES -F auid=0/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b32 -S.*[ ,]'"$module"'[, ].*-F exit=-EPERM -F auid>=500 -F auid!=-1/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b64 -S.*[ ,]'"$module"'[, ].*-F exit=-EPERM -F auid>=500 -F auid!=-1/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b32 -S.*[ ,]'"$module"'[, ].*-F exit=-EPERM -F auid=0/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b64 -S.*[ ,]'"$module"'[, ].*-F exit=-EPERM -F auid=0/' >> $Results; then
  ((scorecheck+=1))
 fi
 done
		
if [ "$scorecheck" != 0 ]; then
 echo "Audit Rules not found" >> $Results
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
