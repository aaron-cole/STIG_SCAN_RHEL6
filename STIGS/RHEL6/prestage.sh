#!/bin/sh
STIGList=( "V-38659" "V-38661" "V-38662" "V-38685" "V-38687" "V-38690" )
TempDIR="./Results"

#Remove File if it exists
if [ -e $TempDIR/prestage ]; then
 rm -rf $TempDIR/prestage
fi

echo ""
echo "Please answer the Following Questions..."

###Check###
for stig in ${STIGList[@]}; do
 case $stig in
   V-38659|V-38661|V-38662)
		PS3="$stig - Does the system require encryption?"
		yesans="System Requires Encryption"
		noans="System Does not Requires Encryption";;
   V-38685) 
		PS3="$stig - Do you provision Temporary Accounts?"
		yesans="Temporary Accounts are provisioned"
		noans="Temporary Accounts are not provisioned";;
   V-38687) 
		PS3="$stig - Does the server communicate over untrusted networks?"
		yesans="Server communicates over untrusted networks"
		noans="Server does not communicate over untrusted networks";;
   V-38690)
		PS3="$stig - Do you provision Emergency Accounts?"
		yesans="Emergency Accounts are provisioned"
		noans="Emergency Accounts are not provisioned";;
 esac
 
 MM=( "Yes" "No" )
 
  #MENU
  select opt in "${MM[@]}" ; do
   case "$REPLY" in
    1)  echo "$stig:$yesans:Fail" >> $TempDIR/prestage
		break;;
    2)  echo "$stig:$noans:Pass" >> $TempDIR/prestage
		break;;
    *) 	echo "Invalid selection, please try again" ;;
   esac
  done
done