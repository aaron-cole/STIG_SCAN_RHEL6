#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#In "iptables" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to "DROP" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted.

#STIG Identification
GrpID="V-218060"
GrpTitle="SRG-OS-000480"
RuleID="SV-218060r603264_rule"
STIGID="RHEL-06-000320"
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

echo "File - $(grep "^:FORWARD DROP \[0:0\]" /etc/sysconfig/iptables)" >> $Results
echo "Running Status - $(service iptables status | grep FORWARD | grep DROP)" >> $Results

if [ "$(grep "^:FORWARD DROP \[0:0\]" /etc/sysconfig/iptables)" ] && [ "$(service iptables status | grep FORWARD | grep DROP)" ];then 
 echo "Pass" >> $Results
else 
  echo "Fail" >> $Results
fi
