#!/bin/bash
# Crack PKCS12 file using a dictionary attack 

DICCIONARIO=$1
ARCHIVO=$2

COUNT=0

for PSW in $(cat $DICCIONARIO)
do
let COUNT+=1
let VAL=COUNT%1000
if [ $VAL -eq 0 ]; then date; echo Intento $COUNT; fi 
if ( openssl pkcs12 -noout -passin pass:${PSW} -in ${ARCHIVO} 2> /dev/null )
then
echo
echo Password found: $PSW
exit
fi
done

