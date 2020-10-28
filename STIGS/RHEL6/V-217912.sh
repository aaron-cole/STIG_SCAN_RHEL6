#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Sending ICMP redirects permits the system to instruct other systems to update their routing information. The ability to send ICMP redirects is only appropriate for systems acting as routers.

#STIG Identification
GrpID="V-217912"
GrpTitle="SRG-OS-000480"
RuleID="SV-217912r505923_rule"
STIGID="RHEL-06-000081"
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

sysctl net.ipv4.conf.all.send_redirects  | awk -v opf="$Results" '/^net.ipv4.conf.all.send_redirects/ {
	if($3 == 0) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}'
