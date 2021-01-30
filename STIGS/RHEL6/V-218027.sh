#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The risk of a system's physical compromise, particularly mobile systems such as laptops, places its data at risk of compromise. Encrypting this data mitigates the risk of its loss if the system is lost.

#STIG Identification
GrpID="V-218027"
GrpTitle="SRG-OS-000480"
RuleID="SV-218027r603264_rule"
STIGID="RHEL-06-000275"
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
TempDIR="./Results"

if [ -e $TempDIR/prestage ]; then
 grep "$GrpID" $TempDIR/prestage | cut -f 2 -d ":" >> $Results
 grep "$GrpID" $TempDIR/prestage | cut -f 3 -d ":" >> $Results
else
PS3="$GrpID - Does the system require encryption?"
MM=( "Yes" "No" )
 
  #MENU
select opt in "${MM[@]}" ; do
 case "$REPLY" in
    1)  echo "System Requires Encryption" >> $Results
		echo "Manual" >> $Results 
		break;;
    2)  echo "System DOES NOT Require Encryption" >> $Results
		echo "Pass" >> $Results
		break;;
    *) 	echo "Invalid selection, please try again" ;;
 esac
done
fi
