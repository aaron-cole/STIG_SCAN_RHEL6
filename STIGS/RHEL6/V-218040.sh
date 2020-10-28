#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Unnecessary services should be disabled to decrease the attack surface of the system.

#STIG Identification
GrpID="V-218040"
GrpTitle="SRG-OS-000095"
RuleID="SV-218040r505923_rule"
STIGID="RHEL-06-000290"
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

echo "Startup Runlevel - $(grep ^id:3:initdefault /etc/inittab)" >> $Results
echo "Running Runlevel - $(runlevel)" >> $Results

if [ "$(grep ^id:3:initdefault /etc/inittab)" ] && [ $(runlevel | cut -f2 -d" ") == "3" ] ; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
