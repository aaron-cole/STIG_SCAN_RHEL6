#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#This prevents attackers with physical access from trivially bypassing security on the machine and gaining root access. Such accesses are further prevented by configuring the bootloader password.

#STIG Identification
GrpID="V-217905"
GrpTitle="SRG-OS-000080"
RuleID="SV-217905r603264_rule"
STIGID="RHEL-06-000069"
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
if [ -e /etc/sysconfig/init ] && [ "$(grep "^SINGLE" /etc/sysconfig/init | wc -l)" -eq 1 ]; then 
awk -v opf="$Results" -F= '/^SINGLE/ {
	if($2 == "/sbin/sulogin") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/sysconfig/init
else
 echo "Setting not defined or more than 1 configuration" >> $Results 
 echo "Fail" >> $Results
fi
