#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#General-purpose systems typically have their network and routing information configured statically by a system administrator. Workstations or some special-purpose systems often use DHCP (instead of IRDP) to retrieve dynamic network configuration information.

#STIG Identification
GrpID="V-218020"
GrpTitle="SRG-OS-000096"
RuleID="SV-218020r505923_rule"
STIGID="RHEL-06-000268"
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

echo "Running Status - $(service rdisc status 2>> $Results)" >> $Results
echo "Startup Status - $(chkconfig rdisc --list 2>> $Results)" >> $Results

if [ "$(service rdisc status 2>>/dev/null | grep "is running")" ] || [ "$(chkconfig rdisc --list 2>>/dev/null | grep -e "\<[1-5]\>:on")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
