#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "/etc/gshadow" file contains group password hashes. Protection of this file is critical for system security.

#STIG Identification
GrpID="V-38448"
GrpTitle="SRG-OS-999999"
RuleID="SV-50248r1_rule"
STIGID="RHEL-06-000037"
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

stat -c %G /etc/gshadow >> $Results

if [ `stat -c %G /etc/gshadow` == "root" ] ; then
 echo "Pass" >> $Results
else
 echo "Fail" >> $Results
fi