#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Unencrypted passwords for remote FTP servers may be stored in ".netrc" files. DoD policy requires passwords be encrypted in storage and not used in access scripts.

#STIG Identification
GrpID="V-218078"
GrpTitle="SRG-OS-000073"
RuleID="SV-218078r505923_rule"
STIGID="RHEL-06-000347"
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

if [ $(find /home /root -xdev -name .netrc >> $Results) ] ; then 
 echo "Fail" >> $Results
else
 echo "No .netrc files found" >> $Results
 echo "Pass" >> $Results 
fi
