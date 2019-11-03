#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "/etc/passwd" file contains information about the users that are configured on the system. Protection of this file is critical for system security.

#STIG Identification
GrpID="V-38450"
GrpTitle="SRG-OS-999999"
RuleID="SV-50250r1_rule"
STIGID="RHEL-06-000039"
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

stat -c %U /etc/passwd >> $Results

if [ `stat -c %U /etc/passwd` == "root" ] ; then
 echo "Pass" >> $Results
else
 echo "Fail" >> $Results
fi