#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Removing the "ypserv" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.

#STIG Identification
GrpID="V-217989"
GrpTitle="SRG-OS-000095"
RuleID="SV-217989r505923_rule"
STIGID="RHEL-06-000220"
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

if rpm -q ypserv >> $Results; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
