#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Using a stronger hashing algorithm makes password cracking attacks more difficult.

#STIG Identification
GrpID="V-217898"
GrpTitle="SRG-OS-000120"
RuleID="SV-217898r603264_rule"
STIGID="RHEL-06-000062"
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
scorecheck=0
mandatoryfiles=( "system-auth" "system-auth-ac" "password-auth" "password-auth-ac" )

for mandatoryfile in ${mandatoryfiles[@]}; do
 if [ "$(grep "^password.*pam_unix.so.*sha512" /etc/pam.d/$mandatoryfile)" ] ; then
  echo "$mandatoryfile - $(grep "^password.*pam_unix.so.*sha512" /etc/pam.d/$mandatoryfile)" >> $Results
 else
  echo "$mandatoryfile - Does not have sha512 defined as required" >> $Results
  ((scorecheck+=1))
 fi
done

for file in $(ls /etc/pam.d/); do
 case "$file" in
	system-auth|system-auth-ac|password-auth|password-auth-ac)
		continue;;
	*)	if [ "$(grep "^password.*pam_unix.so" /etc/pam.d/$file)" ] ; then
		 if [ "$(grep "^password.*pam_unix.so.*sha512" /etc/pam.d/$file)" ] ; then
		  echo "$file - $(grep "^password.*pam_unix.so.*sha512" /etc/pam.d/$file)" >> $Results
		 else
		  echo "$file - pam_unix.so line in use without sha512" >> $Results
		  ((scorecheck+=1))
		 fi
		fi;;
 esac
done
		
if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi  
