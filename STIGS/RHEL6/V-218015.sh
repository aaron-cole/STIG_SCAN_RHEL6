#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Mishandling crash data could expose sensitive information about vulnerabilities in software executing on the local machine, as well as sensitive information from within a process's address space or registers.

#STIG Identification
GrpID="V-218015"
GrpTitle="SRG-OS-000096"
RuleID="SV-218015r505923_rule"
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
