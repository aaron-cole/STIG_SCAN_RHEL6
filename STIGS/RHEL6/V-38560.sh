#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "iptables" service provides the system

#STIG Identification
GrpID="V-38560"
GrpTitle="SRG-OS-000145"
RuleID="SV-50361r2_rule"
STIGID="RHEL-06-000116"
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

echo "Running Status - $(service iptables status)" >> $Results 2>> $Results
echo "Startup Status - $(chkconfig iptables --list)" >> $Results 2>>$Results

if [ "$(service iptables status 2>>/dev/null | grep "iptables: Firewall is not running.")" ] || [ "$(chkconfig iptables --list 2>>/dev/null | grep -e "\<[3-5]\>:off")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
