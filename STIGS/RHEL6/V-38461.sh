#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.

#STIG Identification
GrpID="V-38461"
GrpTitle="SRG-OS-999999"
RuleID="SV-50261r1_rule"
STIGID="RHEL-06-000044"
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

stat -c %a /etc/group >> $Results

if [ `stat -c %a /etc/group` == "644" ] ; then
 echo "Pass" >> $Results
else
 echo "Fail" >> $Results 
fi
