#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "/etc/shadow" file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to root provides the designated owner with access to sensitive information which could weaken the system security posture.

#STIG Identification
GrpID="V-217871"
GrpTitle="SRG-OS-000480"
RuleID="SV-217871r505923_rule"
STIGID="RHEL-06-000033"
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

stat -c %U /etc/shadow >> $Results

if [ `stat -c %U /etc/shadow` == "root" ] ; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
