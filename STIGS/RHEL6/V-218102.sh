#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#In "ip6tables" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to "DROP" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted.

#STIG Identification
GrpID="V-218102"
GrpTitle="SRG-OS-000480"
RuleID="SV-218102r505923_rule"
STIGID="RHEL-06-000523"
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

#Check to see if IPV6 is disabled first
if [ "$(grep "^options ipv6 disable=1" /etc/modprobe.d/*)" ] && [ "$(chkconfig ip6tables --list 2>> $Results | grep -e "\<[1-5]\>:off")" ]; then
 echo "IPV6 is disabled" >> $Results
 echo "NA" >> $Results
elif [ "$(grep "^net.ipv6.conf.all.disable_ipv6 = 1" /etc/sysctl.conf)" ] && [ "$(grep "^net.ipv6.conf.default.disable_ipv6 = 1" /etc/sysctl.conf)" ] && [ "$(! grep "^::1" /etc/hosts)" ]; then
 echo "IPV6 is disabled" >> $Results
 echo "NA" >> $Results
elif grep "^install ipv6 /bin/true" /etc/modprobe.d/* >> $Results; then
 echo "IPV6 is disabled" >> $Results
 echo "NA" >> $Results
else
 echo "File - $(grep ":INPUT DROP \[0:0\]" /etc/sysconfig/ip6tables)" >> $Results
 echo "Running Status - $(service ip6tables status | grep INPUT | grep DROP)" >> $Results
 if [ "$(grep ":INPUT DROP \[0:0\]" /etc/sysconfig/ip6tables)" ] && [ "$(service ip6tables status | grep INPUT | grep DROP)" ]; then
  echo "Pass" >> $Results
 else
  echo "Fail" >> $Results
 fi
fi
