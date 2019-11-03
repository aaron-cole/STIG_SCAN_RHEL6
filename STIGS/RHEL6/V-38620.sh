#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Enabling the "ntpd" service ensures that the "ntpd" service will be running and that the system will synchronize its time to any servers specified. This is important whether the system is configured to be a client (and synchronize only its own clock) or it is also acting as an NTP server to other systems. Synchronizing time is essential for authentication services such as Kerberos, but it is also important for maintaining accurate logs and auditing possible security breaches.

#STIG Identification
GrpID="V-38620"
GrpTitle="SRG-OS-000056"
RuleID="SV-50421r1_rule"
STIGID="RHEL-06-000247"
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

echo "Running Status - $(service ntpd status 2>> $Results)" >> $Results
echo "Startup Status - $(chkconfig ntpd --list 2>> $Results)" >> $Results

if [ "$(service ntpd status 2>>/dev/null | grep "stopped")" ] || [ "$(chkconfig ntpd --list 2>>/dev/null | grep -e "\<[3-5]\>:off")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi