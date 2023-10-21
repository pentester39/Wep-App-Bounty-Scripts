#!/bin/bash     
echo "#use sudo and dont forget to chmod u+x script.sh RUN: ./ WebApp_L1Recon2.sh"
 
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

echo "###STARTING WebApp_L1Recon2### - This is Level 2 of RECON. See WebApp_L1Recon1 for Level 1. This script searches 1 domain that is provided using sudo ./WebApp_L1Recon2.sh -d domain.com, requires following to be installed: unfurl, SubDomainizer-set path to run within script. This finds cloud services urls, SDs, URLs, secrets, etc. Also runs waybackurls (update parameters in script to look for more. By default this tool will look at SUBDOMAINS unless -no-subs inserted into the script. This parses out key endpoints. See script for details. Script also runs nuclei-configure templates as required, build new templates for new vuls released, consider adding addtional templates to look at. Also runs corsy.py for CORS misconfigs, whatweb, Firewall Detection, enum4linux, HTTP request smuggling detecton, smuggler.py, sslscan, wpsscan, nikto, and uses cewl to searh for site emails, Faroxbuster-should sudo apt update prior, can specify filtered codes, etc, "

read -p "Enter path to custom wordlist ffrom assetnote and add wordlist from site or Faroxbuster such as ~/tools/dirsearch/db/dicc.txt: " wordlistpath
echo "using wordlist at " $wordlistpath 
     
echo  "##COMBINED OUTPUT## \n" > WebApp_L1Recon2.txt
echo "searching for WAFs "
echo "##WEB APPLICATION FIREWALL TESTING## – consider for further testing purposes" >> WebApp_L1Recon2.txt
wafw00f $domain >> WebApp_L1Recon2.txt 

echo "starting SubDomainizer for Secrets "
/home/hack39/Desktop/SubDomainizer/SubDomainizer.py -u https://$domain -o secrets.txt  
echo "##Subdomanizer##" >> WebApp_L1Recon2.txt
cat secrets.txt >> WebApp_L1Recon2.txt 

echo "Starting waybackurls "
go run /home/hack39/waybackurls/main.go $domain > waybackurls.txt   
sort waybackurls.txt | uniq -u   
echo "WAYBACK ADMIN \n" >> WebApp_L1Recon2.txt
cat waybackurls.txt | grep admin >> WebApp_L1Recon2.txt
echo "WAYBACK USER \n" >> WebApp_L1Recon2.txt
cat waybackurls.txt | grep user >> WebApp_L1Recon2.txt
echo "WAYBACK USERS \n" >> WebApp_L1Recon2.txt
cat waybackurls.txt | grep users >> WebApp_L1Recon2.txt
echo "WAYBACK EMAIL \n" >> WebApp_L1Recon2.txt
cat waybackurls.txt | grep email >> WebApp_L1Recon2.txt
echo "WAYBACK TOKEN \n" >> WebApp_L1Recon2.txt
cat waybackurls.txt | grep token >> WebApp_L1Recon2.txt
echo "WAYBACK JS \n" >> WebApp_L1Recon2.txt
cat waybackurls.txt | grep js >> WebApp_L1Recon2.txtgo
echo "WAYBACK JS URLs \n" >> WebApp_L1Recon2.txt
cat waybackurls.txt u | grep -P "\w+\.js(\?|$)" >> WebApp_L1Recon2.txt
echo "WAYBACK JSP URLs \n" >> WebApp_L1Recon2.txt
cat waybackurls.txt | grep -P "\w+\.jsp(\?|$)"  >> WebApp_L1Recon2.txt
echo "WAYBACK PASSWORD \n" >> WebApp_L1Recon2.txt
cat waybackurls.txt | grep password >> WebApp_L1Recon2.txt
echo "WAYBACK PASSWORDS \n" >> WebApp_L1Recon2.txt
cat waybackurls.txt | grep passwords >> WebApp_L1Recon2.txt
echo "WAYBACK PHPUrls \n" >> WebApp_L1Recon2.txt
cat waybackurls.txt | grep -P "\w+\.php(\?|$)" >> WebApp_L1Recon2.txt
echo "WAYBACK ASPXUrls \n" >> WebApp_L1Recon2.txt
cat waybackurls.txt | grep -P "\w+\.aspx(\?|$)" >> WebApp_L1Recon2.txt
echo "WAYBACK TXT \n" >> WebApp_L1Recon2.txt
cat waybackurls.txt | grep -P "\w+\.txt(\?|$)" >> WebApp_L1Recon2.txt

cat waybackurls.txt | grep -oP '(?<=\?|&)\w+(?==|&)' > oldparams.txt     
cat waybackurls.txt u | unfurl --unique keys > paramlist.txt
cat paramlist.txt >> oldparams.txt
echo "WAYBACK OLDParams \n" >> WebApp_L1Recon2.txt
cat oldparams.txt >> WebApp_L1Recon2.txt

sort WebApp_L1Recon2.txt | uniq -u       #Removes duplicate lines  

echo "Starting Nuclei "
echo "##NUCLEI## \n" >> WebApp_L1Recon2.txt
echo "##NUCLEI CVEs## \n" >> WebApp_L1Recon2.txt
nuclei -ut   #updates templates
nuclei -u https://$domain -t "/root/tools/nuclei-templates/cves/*.yaml" -c 60 -o cves.txt
cat cves.txt >> WebApp_L1Recon2.txt
echo "##NUCLEI files## \n" >> WebApp_L1Recon2.txt
nuclei -u https://$domain -t "/root/tools/nuclei-templates/files/*.yaml" -c 60 -o files.txt
cat files.txt >> WebApp_L1Recon2.txt
echo "##NUCLEI Panels## \n" >> WebApp_L1Recon2.txt
nuclei -u https://$domain -t "/root/tools/nuclei-templates/panels/*.yaml" -c 60 -o panels.txt
cat panels.txt >> WebApp_L1Recon2.txt
echo "##NUCLEI Security Misconfogurations## \n" >> WebApp_L1Recon2.txt
nuclei -u https://$domain -t "/root/tools/nuclei-templates/security-misconfiguration/*.yaml" -c 60 -o security-misconfiguration.txt
cat security-misconfiguration.txt >> WebApp_L1Recon2.txt
echo "##NUCLEI Technologies## \n" >> WebApp_L1Recon2.txt
nuclei -u https://$domain -t "/root/tools/nuclei-templates/technologies/*.yaml" -c 60 -o technologies.txt
cat technologies.txt >> WebApp_L1Recon2.txt
echo "##NUCLEI Tokens## \n" >> WebApp_L1Recon2.txt
nuclei -u https://$domain -t "/root/tools/nuclei-templates/tokens/*.yaml" -c 60 -o tokens.txt 
cat tokens.txt >> WebApp_L1Recon2.txt
echo "##NUCLEI Vulnerabilities## \n" >> WebApp_L1Recon2.txt
nuclei -u https://$domain -t "/root/tools/nuclei-templates/vulnerabilities/*.yaml" -c 60 -o vulnerabilities.txt
cat vulnerabilities.txt >> WebApp_L1Recon2.txt

echo "Now looking for CORS misconfiguration "
echo "Starting CORS \n"
echo "##CORS MISCONFIGURATIONS## \n" >> WebApp_L1Recon2.txt
python3 /home/hack39/Corsy/corsy.py -u https://$domain -t 40 >> WebApp_L1Recon2.txt

echo "Starting CMS detection_whatweb "
echo "##WHATWEB MISCONFIGURATIONS## \n" >> WebApp_L1Recon2.txt
whatweb -i $domain >> WebApp_L1Recon2.txt

echo "ENUMERATING WINDOWS & SAMBA SYS _ enum4linux "
echo "ENUMERATING WINDOWS & SAMBA SYS _ enum4linux " >> WebApp_L1Recon2.txt
enum4linux $domain URL >> WebApp_L1Recon2.txt

echo "Starting WordPress Enumeration "
echo "WORDPRESS ENUM " >> WebApp_L1Recon2.txt
wpscan –url https://$domain –enumerate p >> WebApp_L1Recon2.txt

echo "Starting SSL SCAN "
echo "SSL SCAN " >> WebApp_L1Recon2.txt
echo “Starting SSL SCAN ”
sslscan $domain >> WebApp_L1Recon2.txt

echo “Starting Feroxbuster ”
echo "##CONTENT DISC W FAROXBUSTER \n" >> WebApp_L1Recon2.txt
feroxbuster -u https://$domain -w wordlistpath -v >> WebApp_L1Recon2.txt

echo "Site emails " 
echo "##SITE EMAILS## " >> WebApp_L1Recon2.txt
cewl https://www.$domain -n -e --with-numbers -d 3 -w siteemails.txt
cat siteemails.txt >> WebApp_L1Recon2.txt

echo "Starting NIKTO " 
echo "##NIKTO EMAILS## \n" >> WebApp_L1Recon2.txt
nikto -h $domain >> WebApp_L1Recon2.txt 

echo "Starting smuggler.py "
echo "##HTTP REQUEST SMUGGLING## \n" >> WebApp_L1Recon2.txt
python3 /home/hack39/smuggler/smuggler.py -u $domain >> WebApp_L1Recon2.txt

rm siteemails.txt oldparams.txt waybackurls.txt paramlist.txt secrets.txt  

echo "END OF SCRIPT - VIEW OUTPUT AT WebApp_L1Recon2.txt " 
