#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Adding host-based intrusion detection tools can provide the capability to automatically take actions in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools also often include a reporting capability to provide network awareness of system, which may not otherwise exist in an organization's systems management regime.

#STIG Identification
GrpID="V-38667"
GrpTitle="SRG-OS-000196"
RuleID="SV-50468r4_rule"
STIGID="RHEL-06-000285"
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

echo "Running Status - $(service isectpd status 2>> $Results)" >> $Results
echo "Startup Status - $(chkconfig isectpd --list 2>> $Results)" >> $Results

if rpm -q ISecTP >> $Results; then
 if [ "$(service isectpd status 2>>/dev/null | grep "not running.")" ] || [ "$(chkconfig isectpd --list 2>>/dev/null | grep -e "\<[3-5]\>:off")" ] ; then 
  echo "McAfee ENSL Installed but not running" >> $Results
  echo "Fail" >> $Results
 else
  /opt/isec/ens/threatprevention/bin/isecav --version >> $Results
  echo "Pass" >> $Results
 fi
else
 echo "Selinux Status - $(getenforce)" >> $Results
 echo "Fail" >> $Results
fi
