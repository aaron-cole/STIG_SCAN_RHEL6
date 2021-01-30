#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Allowing a user account to own a world-writable directory is undesirable because it allows the owner of that directory to remove or replace any files that may be placed in the directory by other users.

#STIG Identification
GrpID="V-218068"
GrpTitle="SRG-OS-000480"
RuleID="SV-218068r603264_rule"
STIGID="RHEL-06-000337"
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

if for p in $(mount | egrep -i "ext|xfs|btrfs|hpfs" | cut -f3 -d" "); do find $p -xdev -type d -perm -0002 -uid +499 -print | grep -v "loop" >> $Results ; done; then 
 echo "Fail" >> $Results
else 
 echo "All public directories are owned by a system account" >> $Results
 echo "Pass" >> $Results
fi
