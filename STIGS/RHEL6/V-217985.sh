#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "rsh-server" package provides several obsolete and insecure network services. Removing it decreases the risk of those services' accidental (or intentional) activation.

#STIG Identification
GrpID="V-217985"
GrpTitle="SRG-OS-000095"
RuleID="SV-217985r603264_rule"
STIGID="RHEL-06-000213"
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

if rpm -q rsh-server >> $Results; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
