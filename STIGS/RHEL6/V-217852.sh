#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The Red Hat GPG keys are necessary to cryptographically verify packages are from Red Hat. 

#STIG Identification
GrpID="V-217852"
GrpTitle="SRG-OS-000366"
RuleID="SV-217852r603264_rule"
STIGID="RHEL-06-000008"
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

if rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey | grep release | sed 's/[<>]//g' >> $Results; then
 echo "Pass" >> $Results
else 
 echo "Not installed" >> $Results
 echo "Fail" >> $Results
fi
