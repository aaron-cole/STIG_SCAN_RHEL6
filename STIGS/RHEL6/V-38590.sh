#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Installing "screen" ensures a console locking capability is available for users who may need to suspend console logins.

#STIG Identification
GrpID="V-38590"
GrpTitle="SRG-OS-000030"
RuleID="SV-50391r1_rule"
STIGID="RHEL-06-000071"
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

if rpm -q screen >> $Results; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi