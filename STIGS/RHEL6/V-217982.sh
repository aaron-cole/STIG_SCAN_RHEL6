#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Removing the "xinetd" package decreases the risk of the xinetd service's accidental (or intentional) activation.

#STIG Identification
GrpID="V-217982"
GrpTitle="SRG-OS-000096"
RuleID="SV-217982r603264_rule"
STIGID="RHEL-06-000204"
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

if rpm -q xinetd >> $Results; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
