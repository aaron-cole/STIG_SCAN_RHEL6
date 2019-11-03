#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Placing "/var/log/audit" in its own partition enables better separation between audit files and other files, and helps ensure that auditing cannot be halted due to the partition running out of space.

#STIG Identification
GrpID="V-38467"
GrpTitle="SRG-OS-000044"
RuleID="SV-50267r1_rule"
STIGID="RHEL-06-000004"
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

if mount | grep "on /var/log/audit " >> $Results; then
 echo "Pass" >> $Results
else
 echo "/var/log/audit not on seperate partition" >> $Results 
 echo "Fail" >> $Results 
fi
