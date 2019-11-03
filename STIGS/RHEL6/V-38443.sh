#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "/etc/gshadow" file contains group password hashes. Protection of this file is critical for system security.

#STIG Identification
GrpID="V-38443"
GrpTitle="SRG-OS-999999"
RuleID="SV-50243r1_rule"
STIGID="RHEL-06-000036"
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

stat -c %U /etc/gshadow >> $Results

if [ `stat -c %U /etc/gshadow` == "root" ] ; then 
 echo "Pass" >> $Results
else
 echo "Fail" >> $Results
fi