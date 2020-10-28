#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#DHCP relies on trusting the local network. If the local network is not trusted, then it should not be used. However, the automatic configuration provided by DHCP is commonly used and the alternative, manual configuration, presents an unacceptable burden in many circumstances.

#STIG Identification
GrpID="V-218042"
GrpTitle="SRG-OS-000095"
RuleID="SV-218042r505923_rule"
STIGID="RHEL-06-000292"
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

if egrep -i "^BOOTPROTO=none|^BOOTPROTO=static" /etc/sysconfig/network-scripts/ifcfg-* >> $Results; then 
 echo "Pass" >> $Results 
else
 grep -i "^BOOTPROTO" /etc/sysconfig/network-scripts/ifcfg-* >> $Results
 echo "Fail" >> $Results
fi
