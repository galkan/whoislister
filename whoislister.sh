#!/usr/bin/env bash

RESET=`tput sgr0`
RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`

DNS_SERVER=8.8.8.8
WHOIS_SERVER=whois.crsnic.net
SERVER_FILE="`mktemp /tmp/$USER.XXXXXX`"


function usage() {
	echo "Usage: $0 [-d <example> ] [-f <@example.com> ] [ -t <thread_count>] [-o <output_file>]" 1>&2
	exit 1
}


while getopts ":d:f:t:o:" p; do
        case "${p}" in
                d)
                        d=${OPTARG}
                        ;;
                f)
                        f=${OPTARG}
                        ;;
		t)
			t=${OPTARG}
			;;
		o)
			o=${OPTARG}
			;;
                *)
                        usage
                        ;;
        esac
done


shift $((OPTIND-1))
if [ -z "${d}" ] || [ -z "${f}" ] || [ -z "${t}" ] || [ -z "${o}" ]
then
	usage
fi


DOMAIN="${d}"
THREAD="${t}"
OUTPUT_FILE="${o}"
EMAIL_DOMAIN_FILE="${f}"

if [ ! -f $EMAIL_DOMAIN_FILE ]
then
	echo "${RED} File: '$EMAIL_DOMAIN_FILE' Doesn't Exists ${RESET}"
	exit 1
fi



declare -A DNS_RECORD
DNS_RECORD=( ["EMAIL"]="MX" ["DNS"]="NS" )



function write_output() {
	
	result="$1"

	echo "$result" >> $OUTPUT_FILE 
}



function sleep_random() {

	random_sleep_time=$(( ( RANDOM % 3 ) + 2 ))
	sleep $random_sleep_time
}


function get_server_list() {

	cat $EMAIL_DOMAIN_FILE | sort -nr | uniq | while read -r domain
	do
 		for key in ${!DNS_RECORD[@]}
		do
			server_type=${key}
			dns_record_type=${DNS_RECORD[${key}]}
	
		        dig @$DNS_SERVER $domain $dns_record_type +short | sed -e "s/\.$//g" | while read -r server
       			do
				if [ $server_type == "EMAIL" ]
				then
       		 	        	server="`echo "$server" | awk '{print $2}'`"	
				fi

				dig @$DNS_SERVER $server A +short | while read -r result
				do
					echo "$server_type:$domain:$server:$result" >> $SERVER_FILE
				done
        		done 
		done
	done	
}



function check_email_dns_mx() {

	domain="$1"
	result_file="$2"

	is_dns_mx="`mktemp /tmp/$USER.XXXXXX`"
	is_whois_nameserver="`mktemp /tmp/$USER.XXXXXX`"
	domain_list="(`cat $EMAIL_DOMAIN_FILE  | sort -nr | uniq | while read -r domain; do echo -n "$domain|"; done | sed -e "s/|$//g"`)"

	grep -Eiq "@$domain_list" "$result_file"
	if [ $? -eq 0 ]
	then
		echo "  ${GREEN}-EMAIL -> $domain ${RESET}"
		write_output "EMAIL -> $domain"
	else
		grep -i "Name Server:" 	"$result_file" | cut -d ":" -f2 | awk '{print $1}' | while read -r name_server
		do
			dig @$DNS_SERVER $name_server A +short | while read -r result
			do
				grep -E "^DNS:" $SERVER_FILE | cut -d ":" -f4 | sort -n | uniq | grep -q "$result"
				if [ $? -eq 0 ]
				then
					rm -f $is_whois_nameserver
					echo "${GREEN}-WHOIS-NAME_SERVER -> $domain ${RESET}"
					write_output "WHOIS-NAME_SERVER -> $domain"
					break
				fi

			done

			if [ ! -f $is_whois_nameserver ]
			then
				break		
			fi
		done

		if [ -f $is_whois_nameserver ]
		then

			for key in ${!DNS_RECORD[@]}
               	 	do
                        	server_type=${key}
                        	dns_record_type=${DNS_RECORD[${key}]}

                        	dig @$DNS_SERVER $domain $dns_record_type +short | sed -e "s/\.$//g" | while read -r server
                        	do
                                	if [ $server_type == "EMAIL" ]
                                	then
                                        	server="`echo "$server" | awk '{print $2}' | tr [A-Z] [a-z]`"
                                	fi

                                	dig @$DNS_SERVER $server A +short 2>/dev/null |  while read -r result
                                	do
						grep -E "^$server_type" "$SERVER_FILE" | cut -d ":" -f4 | sort -n | uniq | grep -q "$result"
						if [ $? -eq 0 ]
						then
                                       			echo "${GREEN}-DNS-$server_type -> $domain ${RESET}"
							write_output "DNS-$server_type -> $domain"
							rm -f $is_dns_mx
							break
						fi
                                	done

					if [ ! -f $is_dns_mx ]
					then
						break
					fi
                        	done
			
				if [ ! -f $is_dns_mx ]
				then
					break
				fi
				
                	done
		fi

		rm -f $is_whois_nameserver $is_dns_mx
	fi
}



function whois_domain() {

	domain="$1"

	whois_result_file="`mktemp /tmp/$USER.XXXXXX`"
	whois $domain >$whois_result_file 2>&1

	check_email_dns_mx "$domain" "$whois_result_file"
	
	rm -f $whois_result_file
}


function whois_extend() {
	
	lookup_domain="$1"

	result_file="`mktemp /tmp/$USER.XXXXXX`"
	whois_result_file="`mktemp /tmp/$USER.XXXXXX`"

	whois -h $WHOIS_SERVER "$lookup_domain*" >$whois_result_file 2>&1
	grep -Ei "^(Domain Name: $lookup_domain|$lookup_domain)" $whois_result_file | while read -r line
        do
		domain="$line"

                echo "$line" | grep -Eq "^Domain Name:"
                if [ $? -eq 0 ]
                then
                        domain="`echo "$line" | cut -d " " -f3`"
                fi

		echo "$domain"
        done | sort -nr | uniq >> $result_file

	rm -f $whois_result_file
	echo "$result_file"
}


function run() {

	result_file="$1"

	cat $result_file | while read -r unique_domain
	do
		for ext in {A..Z} - {0..9}
		do
			whois_extend_result="`whois_extend "$unique_domain$ext"`"
			cat $whois_extend_result | while read -r domain
			do
				while [ 1 ]
				do	
					proc_count=$(ps -ef | grep -Ev "(grep|bash|vi)\s+" | grep -i "whois $DOMAIN" | wc -l)
					if [[ $proc_count -gt $THREAD ]]
					then
						sleep_random			
					else
						whois_domain "$domain" &
						break
					fi
				done
			done

			sleep_random			
		done
	done

	rm -f $result_file
}


function main() {

	init_whois_result="`whois_extend "$DOMAIN"`"
	result_count=$(wc -l $init_whois_result | cut -d " " -f1)

	if [ $result_count -eq 0 ]
	then
		echo "${RED}WhoisExtend Command Fail ${RESET}"
		exit 1
	fi

	result_file="`mktemp /tmp/$USER.XXXXXX`"
	cat $init_whois_result | while read -r extend_domain
	do
		echo "$extend_domain" | cut -d "." -f1
	done | sort -n | uniq >> $result_file

	get_server_list
	run $result_file

	rm -f /tmp/root.* 2>/dev/null
}


##
### Main ..
##

main


