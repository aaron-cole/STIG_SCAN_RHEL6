#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Group-ownership of audit binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The group-ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated.

#STIG Identification
GrpID="V-218032"
GrpTitle="SRG-OS-000258"
RuleID="SV-218032r505923_rule"
STIGID="RHEL-06-000280"
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

if rpm -V audit | grep '^......G' >> $Results; then 
 echo "Fail" >> $Results
else 
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
