#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Unnecessary packages should not be installed to decrease the attack surface of the system.

#STIG Identification
GrpID="V-38676"
GrpTitle="SRG-OS-999999"
RuleID="SV-50477r2_rule"
STIGID="RHEL-06-000291"
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

if rpm -q xorg-x11-server-common >> $Results; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi