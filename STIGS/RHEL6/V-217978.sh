#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Auditing file deletions will create an audit trail for files that are removed from the system. The audit trail could aid in system troubleshooting, as well as detecting malicious processes that attempt to delete log files to conceal their presence.

#STIG Identification
GrpID="V-217978"
GrpTitle="SRG-OS-000064"
RuleID="SV-217978r505923_rule"
STIGID="RHEL-06-000200"
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
modules="rmdir unlink unlinkat rename renameat"

for module in $modules; do
 if ! auditctl -l | awk '/^-a always,exit -F arch=b32 -S .*[^-F key=]'"$module"'[, ].*-F auid>=500 -F auid!=-1/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b64 -S .*[^-F key=]'"$module"'[, ].*-F auid>=500 -F auid!=-1/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b32 -S .*[^-F key=]'"$module"'[, ].*-F auid=0/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b64 -S .*[^-F key=]'"$module"'[, ].*-F auid=0/' >> $Results; then
  ((scorecheck+=1))
 fi
done
		
if [ "$scorecheck" != 0 ]; then
 echo "Audit Rules not found" >> $Results
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi

