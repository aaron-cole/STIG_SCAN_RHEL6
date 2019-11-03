#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-38587"
GrpTitle="SRG-OS-000095"
RuleID="SV-50388r1_rule"
STIGID="RHEL-06-000206"
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

if rpm -q telnet-server >> $Results; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi