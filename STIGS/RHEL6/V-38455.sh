#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "/tmp" partition is used as temporary storage by many programs. Placing "/tmp" in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it.

#STIG Identification
GrpID="V-38455"
GrpTitle="SRG-OS-999999"
RuleID="SV-50255r1_rule"
STIGID="RHEL-06-000001"
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

if mount | awk '/ \/tmp /' >> $Results; then 
 echo "Pass" >> $Results
else
 echo "/tmp not on seperate partition" >> $Results
 echo "Fail" >> $Results
fi

