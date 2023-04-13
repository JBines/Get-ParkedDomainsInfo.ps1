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

Michael Skitt,  Consultant

Find me on:
* Web:     https://theinformationstore.com.au
* LinkedIn:  https://www.linkedin.com/in/joshua-bines-4451534
* Github:    https://github.com/jbines
[VERSION HISTORY / UPDATES]
0.0.1 20220608 - JBines - Created the bare bones.
0.0.2 20230112 - JBines - Updated for public release. 
0.0.3 20230112 - JBines - Added PowerShell 7 Support. 
0.0.4 20230413 - MSkitt - Added SPF and DMARC Output.
#>
[CmdletBinding(DefaultParametersetName='None')] 
Param 
(
       [Parameter(Mandatory = $True)]
       [ValidateNotNullOrEmpty()]
       [String]$InputCSV
)

#Powershell v7
$PSDefaultParameterValues['Invoke-RestMethod:SkipHeaderValidation'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipHeaderValidation'] = $true

$Domains = Import-Csv -Path $InputCSV
If(-Not ($Domains.domains.count -gt 0)){Write-Error "No domains found in input csv file, check heading is 'domains'";Break }

$result = @()

foreach($domain in $domains.domains){
    
    #null var
    $dnsenabled = $null
    $dnsserver = $null
    $rootdomain = $null
    $spfrecord = $null
    $spfrecordString = $null
    $spfEnforcement = $null
    $mxrecord = $null
    $dmarcrecord = $null
    $dmarcrecordstring = $null
    $DMARCEnforcement = $null
    $Response = $null
    $TenantId = $null
    $ApiUrl = $null
    $Response = $null

    $data = @()
    Write-host "Processing domain: $domain"

    #DNS NS Servers
    try{
        $try = Resolve-DnsName -Name $domain -Type NS -ErrorAction Stop
        if($?){
            $dnsenabled = $true
            $dnsserver = $try.NameHost -join ','
        }
    }
    catch{$dnsenabled = $false;$dnsserver = "No"}
    Write-host "        DNS Hosting: $dnsenabled"
    Write-host "             Server: $dnsserver"

    #DNS Root Website
    try{
        $try = Resolve-DnsName -Name $domain -Type A -ErrorAction stop
        if($try.type -eq "A"){$rootdomain = $true}
        Else{$rootdomain = $false}
    }
    catch{$rootdomain = $false}
    Write-host "        Root Website: $rootdomain"

    #MX
    try{
        $try = Resolve-DnsName -Name $domain -Type MX -ErrorAction stop
        if($try.type -eq "MX"){$mxrecord = $try.nameexchange -join ',' }
        Else{$mxrecord = $false}
    }
    catch{$mxrecord = $false}
    Write-host "        MX Record: $mxrecord"

    #SPF
    try{
        $try = Resolve-DnsName -Name $domain -Type TXT -ErrorAction stop | Where-Object{$_.strings -like "v=spf1*"}
        if($try.strings -like "v=spf1*"){
            
            $spfrecord = $true
            $spfrecordString = $try.Strings
            switch -Wildcard ($try.strings | Where-Object{$_ -like "*all"}) {
                '*`?all' { $spfEnforcement = "Neutral" }
                '*~all' {  $spfEnforcement = "SoftFail" }
                '*-all' {  $spfEnforcement = "HardFail" }
                Default { $spfEnforcement = "None" }
            }
        
        }
        else{$spfrecord = $false;$spfEnforcement = "None"}
    }
    catch{$spfrecord = $false;$spfEnforcement = "None"}
    Write-host "        SPF Record: $spfrecordString"
    Write-host "        SPF Record: $spfrecord"
    Write-host "        SPF Enforcement: $spfEnforcement"
    

    #DMARC
    try{
        $try = Resolve-DnsName -Name $("_dmarc."+$domain) -Type TXT -ErrorAction stop
        if($try.strings -like "v=DMARC1*"){

            $dmarcrecord = $true
            $dmarcrecordstring = $try.Strings
            switch -Wildcard ($try.strings | Where-Object{$_ -like "v=DMARC1*"}) {
                '*p`=none*' { $DMARCEnforcement = "None" }
                '*p`=quarantine*' {  $DMARCEnforcement = "Quarantine" }
                '*p`=reject*' {  $DMARCEnforcement = "Reject" }
                Default { $DMARCEnforcement = "None" }
            }
        }
        Else{$dmarcrecord = $false;$DMARCEnforcement = "None"}
    }
    catch{$dmarcrecord = $false;$DMARCEnforcement = "None"}
    Write-host "        Dmarc Record: $dmarcrecordstring"
    Write-host "        Dmarc Record: $dmarcrecord"
    Write-host "        Dmarc Enforcement: $DMARCEnforcement"

#M365 Registered? Confirm Tenant ID

try {
    $headers = @{'Content-Type'="application\json"}

    #This request get users list with signInActivity.
    $ApiUrl = "https://login.microsoftonline.com/$domain/.well-known/openid-configuration"

    $Response = Invoke-WebRequest -Method 'GET' -Uri $ApiUrl -ContentType 'application\json' -Headers $headers | ConvertFrom-Json

    If($Response.token_endpoint){  
        $datePattern = '(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}'
        $responseTokenEndpoint = $Response.token_endpoint | Select-String $datePattern -AllMatches
        $TenantId = $responseTokenEndpoint.Matches.Value
        Write-host "        M365 Tenant: $TenantId"
    }
    else {
        $TenantId = $False
    }

}
catch {
    $TenantId = $False
    Write-host "        M365 Tenant: $TenantId"

}
    $Data = [PSCustomObject]@{
        Domain   = $domain
        DNSEnabled      = $dnsenabled
        dnshost = $dnsserver
        Website            = $rootdomain
        MX_Record           = $mxrecord
        SPF_Record          = $spfrecordString -join ""
        SPF_Record_Found        = $spfrecord
        spfEnforcement = $spfEnforcement
        DMARC_Record = $dmarcrecordstring -join ""
        DMARC_Record_Found  = $dmarcrecord
        DMARCEnforcement = $DMARCEnforcement
        m365TenantId = $TenantId
    } 

    $result += $data
}

$datetime = get-date -format yyyyMMdd_HHmmss
$result | Export-Csv GetParkedDomains_export_$datetime.csv 
