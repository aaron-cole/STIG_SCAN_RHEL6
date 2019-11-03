#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#A TCP SYN flood attack can cause a denial of service by filling a system

#STIG Identification
GrpID="V-38539"
GrpTitle="SRG-OS-000142"
RuleID="SV-50340r2_rule"
STIGID="RHEL-06-000095"
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

sysctl net.ipv4.tcp_syncookies | awk -v opf="$Results" '/^net.ipv4.tcp_syncookies/ {
	if($3 == 1) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}'