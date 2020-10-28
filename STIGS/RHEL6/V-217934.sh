#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Disabling DCCP protects the system against exploitation of any flaws in its implementation.

#STIG Identification
GrpID="V-217934"
GrpTitle="SRG-OS-000096"
RuleID="SV-217934r505923_rule"
STIGID="RHEL-06-000124"
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

grep -r "^install dccp" /etc/modprobe.d >> $Results

if [ "$(grep -r "^install dccp \/bin\/true" /etc/modprobe.d)" ]; then 
 echo "Pass" >> $Results 
else 
 echo "Fail" >> $Results
fi
