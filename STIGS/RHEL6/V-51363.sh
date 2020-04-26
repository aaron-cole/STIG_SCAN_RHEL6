#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Setting the SELinux state to enforcing ensures SELinux is able to confine potentially compromised processes to the security policy, which is designed to prevent them from causing damage to the system or further elevating their privileges. 

#STIG Identification
GrpID="V-51363"
GrpTitle="SRG-OS-999999"
RuleID="SV-65573r2_rule"
STIGID="RHEL-06-000020"
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
 if awk '/^SELINUX=enforcing/' /etc/selinux/config >> $Results; then 
  echo "Pass" >> $Results
 else
  awk '/^SELINUX=/' /etc/selinux/config >> $Results
  echo "Fail" >> $Results
 fi
fi
