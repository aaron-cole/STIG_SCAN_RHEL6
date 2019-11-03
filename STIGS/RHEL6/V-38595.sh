#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Smart card login provides two-factor authentication stronger than that provided by a username/password combination. Smart cards leverage a PKI (public key infrastructure) in order to provide and verify credentials.

#STIG Identification
GrpID="V-38595"
GrpTitle="SRG-OS-000105"
RuleID="SV-50396r3_rule"
STIGID="RHEL-06-000349"
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

function fail {
 echo "Are all users using CAC authentication?" >> $Results
 echo "Fail" >> $Results
}

if [ "$(service sssd status  2>>/dev/null | grep "is running.")" ] && [ "$(chkconfig sssd --list  2>>/dev/null | grep "\<3\>:on")" ] ; then
 if [ "$(grep "^id_provider = ipa" /etc/sssd/sssd.conf)" ] && [ "$(grep "^auth_provider = ipa" /etc/sssd/sssd.conf)" ] && [ "$(grep "access_provider = ipa" /etc/sssd/sssd.conf)" ]; then
  if [ "$(awk '/^auth.*pam_sss.so/' /etc/pam.d/system-auth)" ] && [ "$(awk '/^account.*pam_sss.so/' /etc/pam.d/system-auth)" ]; then
   echo "IDM is in use" >> $Results
   echo "Pass" >> $Results
  else
   fail
  fi
 else
  fail
 fi
else
 fail
fi