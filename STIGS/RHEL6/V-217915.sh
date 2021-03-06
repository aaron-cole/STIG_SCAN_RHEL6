#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Accepting ICMP redirects has few legitimate uses. It should be disabled unless it is absolutely required.

#STIG Identification
GrpID="V-217915"
GrpTitle="SRG-OS-000480"
RuleID="SV-217915r603264_rule"
STIGID="RHEL-06-000084"
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

sysctl net.ipv4.conf.all.accept_redirects  | awk -v opf="$Results" '/^net.ipv4.conf.all.accept_redirects/ {
	if($3 == 0) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}'
