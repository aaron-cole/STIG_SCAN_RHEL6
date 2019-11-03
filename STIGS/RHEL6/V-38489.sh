#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The AIDE package must be installed if it is to be available for integrity checking.

#STIG Identification
GrpID="V-38489"
GrpTitle="SRG-OS-000232"
RuleID="SV-50290r1_rule"
STIGID="RHEL-06-000016"
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

if rpm -q aide >> $Results; then
 echo "Pass" >> $Results
elif ps -ef | grep -i tripwire | grep -v grep >> $Results; then
 echo "Pass" >> $Results
else
 echo "AIDE or Tripwire is not installed" >> $Results
 echo "Fail" >> $Results 
fi
