#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Ignoring bogus ICMP error responses reduces log size, although some activity would not be logged.

#STIG Identification
GrpID="V-217922"
GrpTitle="SRG-OS-000480"
RuleID="SV-217922r603264_rule"
STIGID="RHEL-06-000093"
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

sysctl net.ipv4.icmp_ignore_bogus_error_responses | awk -v opf="$Results" '/^net.ipv4.icmp_ignore_bogus_error_responses/ {
	if($3 == 1) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}'
