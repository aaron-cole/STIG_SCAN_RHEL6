#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Using a stronger hashing algorithm makes password cracking attacks more difficult.

#STIG Identification
GrpID="V-38576"
GrpTitle="SRG-OS-000120"
RuleID="SV-50377r1_rule"
STIGID="RHEL-06-000063"
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

#Not Going to process any more than 1 lines
#Check will fail automatically if set twice
if [ -e /etc/login.defs ] && [ "$(grep "^ENCRYPT_METHOD" /etc/login.defs | wc -l)" -eq 1 ]; then 
awk -v opf="$Results" '/^ENCRYPT_METHOD/ {
	if($2 == "SHA512") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/login.defs
else
 echo "Setting not defined or more than 1 configuration" >> $Results 
 echo "Fail" >> $Results
fi