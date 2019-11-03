#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#This ensures "postfix" accepts mail messages (such as cron job reports) from the local system only, and not from the network, which protects it from network attack.

#STIG Identification
GrpID="V-38622"
GrpTitle="SRG-OS-000096"
RuleID="SV-50423r2_rule"
STIGID="RHEL-06-000249"
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
if [ -e /etc/postfix/main.cf ] && [ "$(grep "^inet_interfaces" /etc/postfix/main.cf | wc -l)" -eq 1 ]; then 
awk -v opf="$Results" -F= '/^inet_interfaces/ {
	if($2 == " localhost") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/postfix/main.cf
else
 echo "File or Setting not found OR multiple entries defined" >> $Results 
 echo "Fail" >> $Results
fi