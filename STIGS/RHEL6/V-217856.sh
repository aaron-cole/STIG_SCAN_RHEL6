#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Ensuring all packages' cryptographic signatures are valid prior to installation ensures the provenance of the software and protects against malicious tampering.

#STIG Identification
GrpID="V-217856"
GrpTitle="SRG-OS-000366"
RuleID="SV-217856r505923_rule"
STIGID="RHEL-06-000015"
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

if grep gpgcheck=0 /etc/yum.repos.d/* >> $Results; then
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results 
 echo "Pass" >> $Results
fi
