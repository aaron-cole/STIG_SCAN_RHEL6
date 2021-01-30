#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If the "/etc/passwd" file is writable by a group-owner or the world the risk of its compromise is increased. The file contains the list of accounts on the system and associated information, and protection of this file is critical for system security.

#STIG Identification
GrpID="V-217879"
GrpTitle="SRG-OS-000480"
RuleID="SV-217879r603264_rule"
STIGID="RHEL-06-000041"
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

stat -c %a /etc/passwd >> $Results

if [ `stat -c %a /etc/passwd` == "644" ] ; then
 echo "Pass" >> $Results
else
 echo "Fail" >> $Results
fi
