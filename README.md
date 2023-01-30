# Get-ParkedDomainsInfo.ps1

````powershell


<#
.SYNOPSIS
This script will allow the BULK export of domain information such as M365 Tenant ID, SPF, DMARC, etc.
Many tools can be used but typically only allow one domain to be checked.  This is impractical when you 
have 1000s of parked domains to review.
 
.DESCRIPTION
This script was created to assess parked domains for past or present security breaches. Most Orgs have 
registered a large number of parked domains. During assessments customers are often suprised to learn 
that many domains are not well protected or have even registered to other M365 tenants. 

Trust me, it happens more more than you would think...  

To prevent attackers from using parked domains for phishing or other attacks you are recommended to 
apply the following DNS settings for all parked/unused domains. 

SPF: Create an SPF record with no permitted senders, which indicates that no IP is authorised to send
 email for your parked domain.

    parkeddomain.com TXT “v=spf1 -all”

DMARC: Policy set to reject to block any bad senders. 

    _dmarc.parkeddomain.com TXT “v=DMARC1;p=reject;rua=mailto:dmarc-rua@dmarcservice.com;”

MX: If you have an A record on your domain, but no MX records, you should create a null MX record to immediately 
fail any email to that domain. Otherwise, a sender server may try to send email to your A record which could be a 
public facing web server outside your control such as a default landing page.

    parkeddomain.com MX “0 .”

## Get-ParkedDomainsInfo.ps1 [-InputCsv <String>] 

.PARAMETER InputCsv
The Inputcsv parameter is for the csv file containing all domains which need to be assessed. 

CSV

Domains
parkeddomain.com

.EXAMPLE
.\Get-ParkedDomainsInfo.ps1 -InputCsv c:\domains.csv

-- DATA EXPORT --

In this example we export information related to the domains listed in the domains.csv file. 

.NOTES
Non-email sending (parked) domains can be used to generate spam email, but they're easy to protect:
https://www.ncsc.gov.uk/blog-post/protecting-parked-domains

How to Find a Microsoft 365 Tenant Identifier:
https://office365itpros.com/2021/03/27/find-microsoft-365-tenant-identifier

M3AAWG Protecting Parked Domains Best Common Practices:
https://www.m3aawg.org/sites/default/files/m3aawg_parked_domains_bcp-2022-06.pdf

[AUTHOR]
Joshua Bines, Consultant
 
[CONTRIBUTORS]
 
Find me on:
* Web:     https://theinformationstore.com.au
* LinkedIn:  https://www.linkedin.com/in/joshua-bines-4451534
* Github:    https://github.com/jbines


[VERSION HISTORY / UPDATES]
0.0.1 20220608 - JBines - Created the bare bones.
0.0.1 20230112 - JBines - Updated for public release. 

#>

````
