#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Unnecessary packages should not be installed to decrease the attack surface of the system.

#STIG Identification
GrpID="V-218010"
GrpTitle="SRG-OS-000095"
RuleID="SV-218010r603264_rule"
STIGID="RHEL-06-000256"
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

if rpm -q openldap-server >> $Results; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
