#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Ignoring ICMP echo requests (pings) sent to broadcast or multicast addresses makes the system slightly more difficult to enumerate on the network.

#STIG Identification
GrpID="V-217921"
GrpTitle="SRG-OS-000480"
RuleID="SV-217921r505923_rule"
STIGID="RHEL-06-000092"
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

sysctl net.ipv4.icmp_echo_ignore_broadcasts  | awk -v opf="$Results" '/^net.ipv4.icmp_echo_ignore_broadcasts/ {
	if($3 == 1) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}'
