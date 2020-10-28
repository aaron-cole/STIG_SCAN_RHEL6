#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Providing the ability for remote users or systems to initiate a secure VPN connection protects information when it is transmitted over a wide area network.

#STIG Identification
GrpID="V-218061"
GrpTitle="SRG-OS-000480"
RuleID="SV-218061r505923_rule"
STIGID="RHEL-06-000321"
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
TempDIR="./Results"

if [ -e $TempDIR/prestage ]; then
 grep "$GrpID" $TempDIR/prestage | cut -f 2 -d ":" >> $Results
 if [ "$(grep "^$GrpID" $TempDIR/prestage | cut -f 3 -d ":")" == "Pass" ] ;then
  echo "NA" >> $Results 
 else
  grep "$GrpID" $TempDIR/prestage | cut -f 3 -d ":" >> $Results
 fi
else
 if rpm -q libreswan >> $Results; then 
  echo "Pass" >> $Results
 else
  echo "Fail" >> $Results
 fi
fi
