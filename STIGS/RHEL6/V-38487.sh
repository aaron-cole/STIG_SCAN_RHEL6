#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Ensuring all packages

#STIG Identification
GrpID="V-38487"
GrpTitle="SRG-OS-000103"
RuleID="SV-50288r1_rule"
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
