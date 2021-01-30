#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Ensuring that "/home" is mounted on its own partition enables the setting of more restrictive mount options, and also helps ensure that users cannot trivially fill partitions used for log or audit data storage.

#STIG Identification
GrpID="V-217851"
GrpTitle="SRG-OS-000480"
RuleID="SV-217851r603264_rule"
STIGID="RHEL-06-000007"
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

if mount | grep "on /home" >> $Results; then
 echo "Pass" >> $Results
else
 echo "/home not on seperate partition" >> $Results 
 echo "Fail" >> $Results
fi
