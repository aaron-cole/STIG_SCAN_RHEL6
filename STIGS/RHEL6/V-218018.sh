#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "oddjobd" service may provide necessary functionality in some environments but it can be disabled if it is not needed. Execution of tasks by privileged programs, on behalf of unprivileged ones, has traditionally been a source of privilege escalation security issues.

#STIG Identification
GrpID="V-218018"
GrpTitle="SRG-OS-000096"
RuleID="SV-218018r505923_rule"
STIGID="RHEL-06-000266"
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
echo "Running Status - $(service oddjobd status 2>> $Results)" >> $Results
echo "Startup Status - $(chkconfig oddjobd --list 2>> $Results)" >> $Results

function fail {

if [ "$(service oddjobd status 2>>/dev/null | grep "is running.")" ] || [ "$(chkconfig oddjobd --list 2>>/dev/null | grep -e "\<[1-5]\>:on")" ] ; then 
 echo "Fail" >> $Results
else 
 echo "Pass" >> $Results
fi
}

if [ "$(service sssd status 2>>/dev/null | grep "is running.")" ] && [ "$(chkconfig sssd --list 2>>/dev/null | grep "\<3\>:on")" ] ; then
 if [ "$(grep "^id_provider = ipa" /etc/sssd/sssd.conf)" ] && [ "$(grep "^auth_provider = ipa" /etc/sssd/sssd.conf)" ] && [ "$(grep "access_provider = ipa" /etc/sssd/sssd.conf)" ]; then
  if [ "$(awk '/^auth.*pam_sss.so/' /etc/pam.d/system-auth)" ] && [ "$(awk '/^account.*pam_sss.so/' /etc/pam.d/system-auth)" ]; then
   if grep "pam_oddjob_mkhomedir.so" /etc/pam.d/system-auth-ac >> $Results; then
    echo "IDM is in use and needs oddjobd" >> $Results
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
else
 fail
fi


