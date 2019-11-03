#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Inconsistency in GIDs between /etc/passwd and /etc/group could lead to a user having unintended rights.

#STIG Identification
GrpID="V-38681"
GrpTitle="SRG-OS-999999"
RuleID="SV-50482r2_rule"
STIGID="RHEL-06-000294"
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

if pwck -r | grep "no group" >> $Results; then 
 echo "Fail" >> $Results
else
 echo "Nothing Found" >> $Results 
 echo "Pass" >> $Results
fi