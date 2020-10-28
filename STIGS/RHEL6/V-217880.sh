#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.

#STIG Identification
GrpID="V-217880"
GrpTitle="SRG-OS-000480"
RuleID="SV-217880r505923_rule"
STIGID="RHEL-06-000042"
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

stat -c %U /etc/group >> $Results

if [ `stat -c %U /etc/group` == "root" ] ; then 
 echo "Pass" >> $Results
else
 echo "Fail" >> $Results
fi
