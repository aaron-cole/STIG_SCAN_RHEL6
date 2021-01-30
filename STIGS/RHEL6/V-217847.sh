#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Ensuring that "/var" is mounted on its own partition enables the setting of more restrictive mount options. This helps protect system services such as daemons or other programs which use it. It is not uncommon for the "/var" directory to contain world-writable directories, installed by other software packages.

#STIG Identification
GrpID="V-217847"
GrpTitle="SRG-OS-000480"
RuleID="SV-217847r603264_rule"
STIGID="RHEL-06-000002"
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

if mount | awk '/ \/var /' >> $Results; then
 echo "Pass" >> $Results
else
 echo "/var not on seperate partition" >> $Results
 echo "Fail" >> $Results
fi

