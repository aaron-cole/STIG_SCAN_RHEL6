#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Accepting "secure" ICMP redirects (from those gateways listed as default gateways) has few legitimate uses. It should be disabled unless it is absolutely required.

#STIG Identification
GrpID="V-38532"
GrpTitle="SRG-OS-999999"
RuleID="SV-50333r3_rule"
STIGID="RHEL-06-000090"
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

sysctl net.ipv4.conf.default.secure_redirects  | awk -v opf="$Results" '/^net.ipv4.conf.default.secure_redirects/ {
	if($3 == 0) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}'
