#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#An illicit ICMP redirect message could result in a man-in-the-middle attack.

#STIG Identification
GrpID="V-38548"
GrpTitle="SRG-OS-999999"
RuleID="SV-50349r3_rule"
STIGID="RHEL-06-000099"
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
#Check to see if IPV6 is disabled first
if [ "$(grep "^options ipv6 disable=1" /etc/modprobe.d/*)" ] && [ "$(chkconfig ip6tables --list 2>> $Results | grep -e "\<[1-5]\>:off")" ]; then
 echo "IPV6 is disabled" >> $Results
 echo "NA" >> $Results
elif [ "$(grep "^net.ipv6.conf.all.disable_ipv6 = 1" /etc/sysctl.conf)" ] && [ "$(grep "^net.ipv6.conf.default.disable_ipv6 = 1" /etc/sysctl.conf)" ] && [ "$(! grep "^::1" /etc/hosts)" ]; then
 echo "IPV6 is disabled" >> $Results
 echo "NA" >> $Results
elif grep "^install ipv6 /bin/true" /etc/modprobe.d/* >> $Results; then
 echo "IPV6 is disabled" >> $Results
 echo "NA" >> $Results
else
 sysctl net.ipv6.conf.default.accept_redirects  | awk -v opf="$Results" '/^net.ipv6.conf.default.accept_redirects/ {
	if($3 == 0) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}'
fi