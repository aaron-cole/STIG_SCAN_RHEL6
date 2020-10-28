#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If a device file carries the SELinux type "unlabeled_t", then SELinux cannot properly restrict access to the device file. 

#STIG Identification
GrpID="V-217864"
GrpTitle="SRG-OS-000324"
RuleID="SV-217864r505923_rule"
STIGID="RHEL-06-000025"
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
if ls -RZ /dev | grep unlabeled_t >> $Results; then 
 echo "Fail" >> $Results
else
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
