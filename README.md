# Wep-App-Bounty-Scripts by pentester39
I welcome comments and suggested updates to these scripts. I could use a better way to display combined results.  
Install requirements written within the scripts. RUN using sudo ./script.sh -d domain.com
SUMMARY: Series of RECON automation scripts that take customized wordlists, templates, etc and outputs into one file - can use for Bug Bounty Web Application Testing, pentexting Apps, etc.
WebApp_L1Recon1.sh is for SubDomain finding.
WebApp_L1Recon2 takes recon a bit further to find interesting content. This script searches 1 domain that is provided. Requires following to be installed: unfurl, SubDomainizer, waybackurls (update parameters in script to look for additional endpoints), nuclei-configure templates as required, build new templates for new vulnerabilities released, consider adding addtional templates to look at. Script also runs corsy.py for CORS misconfigs, whatweb, Firewall Detection, enum4linux, HTTP request smuggling detecton, smuggler.py, sslscan, wpsscan, nikto, and uses cewl to searh for site emails, faroxbuster for content discovery - should sudo apt update prior, can specify filtered codes, etc, "
See scrip for individual tools that need to be installed, API keys, etc required to run it.
