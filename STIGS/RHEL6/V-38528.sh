#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The presence of "martian" packets (which have impossible addresses) as well as spoofed packets, source-routed packets, and redirects could be a sign of nefarious network activity. Logging these packets enables this activity to be detected.

#STIG Identification
GrpID="V-38528"
GrpTitle="SRG-OS-999999"
RuleID="SV-50329r2_rule"
STIGID="RHEL-06-000088"
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

sysctl net.ipv4.conf.all.log_martians | awk -v opf="$Results" '/^net.ipv4.conf.all.log_martians/ {
	if($3 == 1) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}'