#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Mishandling crash data could expose sensitive information about vulnerabilities in software executing on the local machine, as well as sensitive information from within a process

#STIG Identification
GrpID="V-38640"
GrpTitle="SRG-OS-000096"
RuleID="SV-50441r2_rule"
STIGID="RHEL-06-000261"
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

echo "Running Status - $(service abrtd status 2>> $Results)" >> $Results
echo "Startup Status - $(chkconfig abrtd --list 2>> $Results)" >> $Results

if [ "$(service abrtd status 2>>/dev/null | grep "is running")" ] || [ "$(chkconfig abrtd --list 2>>/dev/null | grep -e "\<[1-5]\>:on")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi