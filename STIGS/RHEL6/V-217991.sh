#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Removing the "tftp-server" package decreases the risk of the accidental (or intentional) activation of tftp services.

#STIG Identification
GrpID="V-217991"
GrpTitle="SRG-OS-000095"
RuleID="SV-217991r505923_rule"
STIGID="RHEL-06-000222"
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

if rpm -q tftp-server >> $Results; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
