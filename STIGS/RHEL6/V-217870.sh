#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#An account has root authority if it has a UID of 0. Multiple accounts with a UID of 0 afford more opportunity for potential intruders to guess a password for a privileged account. Proper configuration of sudo is recommended to afford multiple system administrators access to root privileges in an accountable manner.

#STIG Identification
GrpID="V-217870"
GrpTitle="SRG-OS-000480"
RuleID="SV-217870r603264_rule"
STIGID="RHEL-06-000032"
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

if grep -v root /etc/passwd | cut -f3 -d: | grep "^0$" >> $Results; then
 echo "Fail" >> $Results 
else 
 echo "Root is only UID of 0" >> $Results
 echo "Pass" >> $Results
fi
