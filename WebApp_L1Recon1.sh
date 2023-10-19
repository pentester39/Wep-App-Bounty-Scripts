#!/bin/bash   
  
while getopts ":d:" input;do
        case "$input" in
                d) domain=${OPTARG}
                        ;;
                esac
        done
if [ -z "$domain" ]    
        then
                echo "Please give a domain like \"-d domain.com\""
                exit 1
fi 

echo "Run this script with sudo "
echo "###STARTING WebApp_L1Recon1 - SubDomains### - This script requires: subfinder (API Keys should be added to ~/.config/subfinder/provider-config.yaml + customized wordlist), sublist3r, assetfinder, amass, altdns (VERIFY ~/tools/recon/patterns.txt) and httprobe \n"         

echo "Commencing Subfinder"
read -p "Enter path to custom wordlist for subfinder such as /path/wordlist: " customwordlistpath
echo "using wordlist at " $customwordlistpath 

subfinder -d $domain -all -v -o subdomains1.txt 
cat subdomains1.txt > sD.txt
subfinder -d $domain -v -w $customwordlistpath -o subdomains2.txt 
cat subdomains2.txt >> sD.txt

echo "Commencing Sublister"
sublist3r -d $domain -b -t 2 -v -o subdomains3.txt
cat subdomains3.txt >> sD.txt 

echo "Commencing assetfinder"
assetfinder --subs-only $domain | tee -a allsubdomains.txt

echo "Commencing amass"
amass enum -passive -d $doamin | tee -a allsubdomains1.txt
amass enum -active -d $domain | tee -a amass_ips.txt
cat amass_ips.txt | awk '{print $1}' | tee -a allsubdomains3.txt
cat allsubdomains.txt >> sD.txt
cat allsubdomains1.txt >> sD.txt
cat allsubdomains3.txt >> sD.txt
cat amass_ips.txt >> sD.txt

echo -e "Commencing subdomain disc thru alterations and permutations _ using bruteforce \n"
altdns -i SD.txt -o data_output -w ~/tools/recon/patterns.txt -r -s output.txt
cat output.txt >> sD.txt

cat sD.txt | sort -u > SDRecon.txt

echo "\n\n " >> SDRecon.txt
echo "LIVE DOMAINS \n\n" >> SDRecon.txt
cat SDRecon.txt | httprobe >> live.txt
cat live.txt >> SDRecon.txt

echo "END OF SCIPT. RESULTS FOR ALL LIVE SUBDOMAINs saved in SDRecon.txt" 

