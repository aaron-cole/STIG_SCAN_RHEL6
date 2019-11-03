#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Setting the SELinux state to enforcing ensures SELinux is able to confine potentially compromised processes to the security policy, which is designed to prevent them from causing damage to the system or further elevating their privileges. 

#STIG Identification
GrpID="V-51363"
GrpTitle="SRG-OS-999999"
RuleID="SV-65573r1_rule"
STIGID="RHEL-06-000020"
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

if awk '/^SELINUX=enforcing/' /etc/selinux/config >> $Results; then 
 echo "Pass" >> $Results
else
 awk '/^SELINUX=/' /etc/selinux/config >> $Results
 echo "Fail" >> $Results
fi