#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#IP forwarding permits the kernel to forward packets from one network interface to another. The ability to forward packets between two networks is only appropriate for systems acting as routers.

#STIG Identification
GrpID="V-38511"
GrpTitle="SRG-OS-999999"
RuleID="SV-50312r3_rule"
STIGID="RHEL-06-000082"
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

sysctl net.ipv4.ip_forward  | awk -v opf="$Results" '/^net.ipv4.ip_forward/ {
	if($3 == 0) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}'
