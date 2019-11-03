#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "ip6tables" service provides the system

#STIG Identification
GrpID="V-38551"
GrpTitle="SRG-OS-000145"
RuleID="SV-50352r3_rule"
STIGID="RHEL-06-000106"
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
 echo "Running Status - $(service ip6tables status)" >> $Results 2>> $Results
 echo "Startup Status - $(chkconfig ip6tables --list)" >> $Results 2>>$Results
 if [ "$(service ip6tables status 2>>/dev/null | grep "ip6tables: Firewall is not running.")" ] || [ "$(chkconfig ip6tables --list 2>>/dev/null | grep -e "\<[3-5]\>:off")" ] ; then 
  echo "Fail" >> $Results
 else
  echo "Pass" >> $Results
 fi
fi