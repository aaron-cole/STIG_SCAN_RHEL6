#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Allowing insecure file locking could allow for sensitive data to be viewed or edited by an unauthorized user.

#STIG Identification
GrpID="V-218055"
GrpTitle="SRG-OS-000104"
RuleID="SV-218055r505923_rule"
STIGID="RHEL-06-000309"
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

if grep insecure_locks /etc/exports >> $Results; then
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results 
 echo "Pass" >> $Results
fi
