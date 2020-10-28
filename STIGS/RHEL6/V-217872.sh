#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "/etc/shadow" file stores password hashes. Protection of this file is critical for system security.

#STIG Identification
GrpID="V-217872"
GrpTitle="SRG-OS-000480"
RuleID="SV-217872r505923_rule"
STIGID="RHEL-06-000034"
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

stat -c %G /etc/shadow >> $Results

if [ `stat -c %G /etc/shadow` == "root" ] ; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
