#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "sudo" command allows authorized users to run programs (including shells) as other users, system users, and root. The "/etc/sudoers" file is used to configure authorized "sudo" users as well as the programs they are allowed to run. Some configuration options in the "/etc/sudoers" file allow configured users to run programs without re-authenticating. Use of these configuration options makes it easier for one compromised account to be used to compromise other accounts.

#STIG Identification
GrpID="V-58901"
GrpTitle="SRG-OS-000373"
RuleID="SV-73331r2_rule"
STIGID="RHEL-06-000529"
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
if egrep "^[^#]*NOPASSWD|^[^#]*!authenticate" /etc/sudoers >> $Results; then 
 echo "Fail" >> $Results
else 
 if egrep -r "^[^#]*NOPASSWD|^[^#]*\!authenticate" /etc/sudoers.d >> $Results; then 
  echo "Fail" >> $Results
 else 
  echo "Nothing Found in /etc/sudoers.d/ files" >> $Results
  echo "Pass" >> $Results 
 fi 
fi
}

if [ "$(service sssd status 2>>$Results | grep "is running.")" ] && [ "$(chkconfig sssd --list 2>>$Results | grep "\<3\>:on")" ] ; then
 if [ "$(grep "^id_provider = ipa" /etc/sssd/sssd.conf)" ] && [ "$(grep "^auth_provider = ipa" /etc/sssd/sssd.conf)" ] && [ "$(grep "access_provider = ipa" /etc/sssd/sssd.conf)" ]; then
  if [ "$(awk '/^auth.*pam_sss.so/' /etc/pam.d/system-auth)" ] && [ "$(awk '/^account.*pam_sss.so/' /etc/pam.d/system-auth)" ]; then
   echo "IDM is in use" >> $Results
   echo "NA" >> $Results
  else
   fail
  fi
 else
  fail
 fi
else
 fail
fi