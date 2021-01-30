#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "/etc/passwd" file contains information about the users that are configured on the system. Protection of this file is critical for system security.

#STIG Identification
GrpID="V-217878"
GrpTitle="SRG-OS-000480"
RuleID="SV-217878r603264_rule"
STIGID="RHEL-06-000040"
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

stat -c %G /etc/passwd >> $Results

if [ `stat -c %G /etc/passwd` == "root" ] ; then 
 echo "Pass" >> $Results
else
 echo "Fail" >> $Results
fi
