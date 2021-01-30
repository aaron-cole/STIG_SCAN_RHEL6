#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The unauthorized exportation of data to external media could result in an information leak where classified information, Privacy Act information, and intellectual property could be lost. An audit trail should be created each time a filesystem is mounted to help identify and guard against information loss.

#STIG Identification
GrpID="V-217977"
GrpTitle="SRG-OS-000064"
RuleID="SV-217977r603264_rule"
STIGID="RHEL-06-000199"
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

 if ! auditctl -l | awk '/^-a always,exit -F arch=b32 -S.*[ ,]mount[, ].*-F auid>=500 -F auid!=-1/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b64 -S.*[ ,]mount[, ].*-F auid>=500 -F auid!=-1/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b32 -S.*[ ,]mount[, ].*-F auid=0/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b64 -S.*[ ,]mount[, ].*-F auid=0/' >> $Results; then
  ((scorecheck+=1))
 fi
		
if [ "$scorecheck" != 0 ]; then
 echo "Audit Rules not found" >> $Results
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
