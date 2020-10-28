#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "/etc/passwd" file contains information about the users that are configured on the system. Protection of this file is critical for system security.

#STIG Identification
GrpID="V-217877"
GrpTitle="SRG-OS-000480"
RuleID="SV-217877r505923_rule"
STIGID="RHEL-06-000039"
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

stat -c %U /etc/passwd >> $Results

if [ `stat -c %U /etc/passwd` == "root" ] ; then
 echo "Pass" >> $Results
else
 echo "Fail" >> $Results
fi
