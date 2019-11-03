#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Approved algorithms should impart some level of confidence in their implementation. These are also required for compliance.

#STIG Identification
GrpID="V-38617"
GrpTitle="SRG-OS-000169"
RuleID="SV-50418r2_rule"
STIGID="RHEL-06-000243"
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

if grep Ciphers /etc/ssh/sshd_config | egrep -vi "#|arcfour|cbc|blowfish|cast" | egrep "aes128-ctr|aes192-ctr|aes256-ctr" >> $Results ; then 
 echo "Pass" >> $Results
else
 grep Ciphers /etc/ssh/sshd_config | grep -v "#" >> $Results 
 echo "Fail" >> $Results
fi
