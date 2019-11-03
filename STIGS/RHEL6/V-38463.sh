#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Placing "/var/log" in its own partition enables better separation between log files and other files in "/var/".

#STIG Identification
GrpID="V-38463"
GrpTitle="SRG-OS-999999"
RuleID="SV-50263r1_rule"
STIGID="RHEL-06-000003"
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

if mount | grep "on /var/log " >> $Results; then
 echo "Pass" >> $Results
else
 echo "/var/log not on seperate partition" >> $Results 
 echo "Fail" >> $Results 
fi
