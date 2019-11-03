#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Using a stronger hashing algorithm makes password cracking attacks more difficult.

#STIG Identification
GrpID="V-38577"
GrpTitle="SRG-OS-000120"
RuleID="SV-50378r1_rule"
STIGID="RHEL-06-000064"
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

if awk '/\[defaults\]/{flag=1;next}/\[.*\]/{flag=0}flag' /etc/libuser.conf | awk '/^crypt_style = sha512/' >> $Results; then
 echo "Pass" >> $Results
else
 echo "Setting Not Defined" >> $Results 
 echo "Fail" >> $Results
fi
