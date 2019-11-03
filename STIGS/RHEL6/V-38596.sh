#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Address space layout randomization (ASLR) makes it more difficult for an attacker to predict the location of attack code he or she has introduced into a process

#STIG Identification
GrpID="V-38596"
GrpTitle="SRG-OS-999999"
RuleID="SV-50397r2_rule"
STIGID="RHEL-06-000078"
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

sysctl kernel.randomize_va_space  | awk -v opf="$Results" '/^kernel.randomize_va_space/ {
	if($3 == 2) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else if($3 == 1) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}'