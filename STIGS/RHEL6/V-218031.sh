#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Ownership of audit binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated.

#STIG Identification
GrpID="V-218031"
GrpTitle="SRG-OS-000257"
RuleID="SV-218031r505923_rule"
STIGID="RHEL-06-000279"
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

if rpm -V audit | grep '^.....U' >> $Results; then 
 echo "Fail" >> $Results
else 
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
