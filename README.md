# Direct Cyber Proactive Disaster Response Playbook

## The Why

Exploitation of high severity vulnerabilities in internet facing assets leads to the mass deployment of ransomware and extortion based on data exfiltration. We have seen this again and again, all the way back from 2017 with EternalBlue to 2023's MOVEit and CitrixBleed vulnerabilities.

The government and private sector isn't doing enough for organizations that have little to none cyber security awareness nor budget. Patching has largely been an ad-hoc process done days if not weeks after the public disclosure of vulnerabilities, while active exploitation begin in just hours within the release of any new information (technical details, vendor patch, proof of concepts, etc.)

Cyber criminals move FAST - we have to move much faster than them, by sending high severity alerts to vulnerable organizations with little security budget such as hospitals, schools, NFPs, NGOs, charities and critical infrastructure.

## Identifying vulnerabilities to track

The risk of each CVE can be determined by:
- CVSS (Common Vulnerability Scoring System), which determines its severity (as well as other things like environmental factors in CVSS v4)
- EPSS (Exploit Prediction Scoring System), which determines the likely hood for exploit

A general risk score can be calculated by CVSS * EPSS, to a score out of 10.

It also depends on the technical nature of vulnerability, for example:
- Does it lead to Remote Code Execution/RCE?
- Does it require authentication (if it does, we are likely not interested)
- Is the vulnerable software a server? Is it typically internet facing (e.g. a firewall appliance or VPN gateway is typically a good internet facing target)
- Is an exploit available? How hard is it to create one? (technical difficulty)

Additional research may need to be done to determine these factors later on.

Typically if the vulnerability is already actively exploited, does lead to ransomware deployments, and is unauthenticated, then we should prioritize it. If it looks really like a CVE in the past that was actively exploited in that nature, we would also want to jump on that in advance (despite it being more difficult, because there will be more research needed when a Proof Of Concept / PoC is not available).

### Threat intel sources

Threat intelligence is a fancy word for "what's going on". Which vulnerabilities are being exploited? Which ransomware gangs are pwning everyone? What should be patched right now?

These official sources are great for current government alerts:

- https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories
- https://www.cisa.gov/news-events/cybersecurity-advisories
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Github has an extensive security advisory DB that covers third party vulns and allow filtering:

- https://github.com/advisories?query=severity%3Acritical

CVEs being discussed on Mastodon / Fediverse sites:

- https://fedisecfeeds.github.io/
- https://cvecrowd.com

Other sources to follow for current events:

- https://www.bleepingcomputer.com/
- https://therecord.media/
- https://risky.biz/ (Risky Business newsletter and podcast)
- https://doublepulsar.com/ (Kevin Beaumont, aka GossiTheDog)

Vulnerability alerting services:

- https://alerts.vulmon.com/

That's just the start, don't limit yourself to those sources. Look widely, [DuckDuckGo](https://duckduckgo.com/) is your friend.


## Vulnerable hosts identification

We can use [Shodan](https://shodan.io) to query for software that might be vulnerable to a CVE, based on [filters](https://www.shodan.io/search/filters). For the purposes of local response, always add `country:AU` (or whatever the intended region is) for the search.

The Shodan CLI should first be used to gather stats (https://help.shodan.io/command-line-interface/3-stats) of your query, because getting results cost Shodan credits. Each 100 results (which is the standard size of a result page) cost 1 credit. Each [membership-tier user](https://account.shodan.io/billing) has 100 query credits per month, which means 10000 results.

### Finding queries

Find analysis of the vulnerability online, and look for people posting shodan queries and screenshots. Screenshots of shodan results can sometimes contain queries or a hint of what they query might be.

The [awesome-shodan-queries](https://github.com/jakejarvis/awesome-shodan-queries) repo has a lot of example shodan queries.

You can also find shared queries by other users by searching in Shodan's Explore area like so: https://www.shodan.io/explore/search?query=citrix

### Using keywords

You can search using the product's name as a keyword, for example `Citrix` or `Outlook`.

### Using ports

If the vulnerable software only runs on one standard port, then you can search using the port filter e.g. `port:445`

Any number of queries can be combined, for example `port:445 samba` to get any hosts with port 445 open with the string samba in it.

Multiple values can also be specified in any filter, such as `port:445,3389` or `country:AU,NZ` for friends across the ditch.

### Using product and version

Sometimes shodan might label a product accurately. For example, `product:"VMware vCenter Server"`

For some products, the version can be determined by shodan, and you can use that in your filter:

`product:"VMware vCenter Server" version:"6.7.0"`



### Using favicon hash

For web applications, you can use the favicon's hash (if there's a favicon). To get one, use this script with the favicon's URL: https://github.com/Mr-P-D/Favicon-Hash-For-Shodan.io/blob/master/get_favicon_hash.py

For an exploration of favicons, use https://faviconmap.shodan.io/

Then you can search the favicon hash on Shodan like so: `http.favicon.hash:12345`

### Other internet search engines

- https://viz.greynoise.io/ - Greynoise is like a "reverse Shodan". It's useful for finding infected hosts that are acting as part of a botnet. It has a network of honeypots (a lot of which will show up in our shodan searches) that pretends to be certain services and captures exploits, then tags them by destination ports, IP information and vulnerabilities the source IP attempted to exploit. 

- https://fofa.info - has a better product tagging system than Shodan, and there's a good amount of documentation on  [Awesome-FOFA](https://github.com/FofaInfo/Awesome-FOFA) such as a [guide to tracking APT infrastructure via intel pivoting](https://github.com/FofaInfo/Awesome-FOFA/blob/main/Basic%20scenario/Conducting%20APT%20Bitter%20Tracking%20Operation%20Using%20FOFA.md)

- https://www.criminalip.io/ - has semi-frequent blogs on finding devices on the internet based on new trending vulns

- https://search.censys.io - Censys is a more feature complete and aggressive scanner (scans a lot more services and ports); but their API is way less accessible than Shodan in terms of pricing and restrictions

- https://www.zoomeye.org/

- https://leakix.net


## Note on VPNs

For any active network interaction with other servers, **use a VPN if you want to protect your home address**. Using a VPN exit region as the same country as the server you're investigating (e.g. For Australia, use a VPN location in Sydney) can help put your target at ease; where as using offshore VPN locations in a more suspicious country might put them on alert.

Great no-log VPN providers are Mullvad, SurfShark, ProtonVPN and so on.

## Vulnerability research

The target outcome of vulnerability research in this context is gaining the ability to **reliably determine if a host is vulnerable**. 

The quickest way to do this is to find PoCs on Github. You can use dorks on your search engine like so `site:github.com CVE-2023-12345` to find related content on github about the CVE. Sometimes the exploit isn't linked to the CVE number, so you might need to use the name of the vulnerability (like `site:github.com eternalblue`)


Importance of this cannot be overstated:

**ALWAYS READ THE CODE OF POCS!!**

**ALWAYS READ THE CODE OF POCS!!**

**ALWAYS READ THE CODE OF POCS!!**

If you don't read and understand the PoC, don't use it.

Look for checker scripts that can determine if the host is vulnerable without any modification to the target system. If the PoC contains both a check and an exploit, **disarm the exploit functionality** and **make sure it's disarmed** before running it against any live system.


### Legal concerns

Proof of concepts can cause unknown harm to your own system and/or someone else's, and doing so would be illegal. The wording in [Cybercrime Act of 2001](https://www.legislation.gov.au/Details/C2004C01213) prohibits unauthorized **Access**, **Modification** and **Impairment** of a computer system. 

That means checking scripts should not store any sensitive data about the target system (especially passwords, customer data, credit card numbers and so on), merely output the target being vulnerable or not, with potentially debug information such as version numbers.

- **Access** means display of it on screen, copying to another computer, or storage on disk

- **Impairment** means any potential Denial of Service (do not run DOS exploits that can shutdown or cause availability outage)

- **Modification** includes if any new posts, database entries, users etc. are made. If an exploit adds a user for a PoC check, don't use it. Also includes things like stored XSS. Creation of new log lines do not count, because otherwise any web browsing would be illegal.

Note that it is not **a criminal offense to attempt**; that means if you accidentally or otherwise ran something that may cause damage to another system, but it did not cause actual material impact.

**By using this playbook, you acknowledge that DirectCyber is NOT RESPONSIBLE for any law you violate following it.** This playbook is designed for you to safely perform a service to society without breaking the law.

### Using Nuclei

ProjectDiscovery's [Nuclei](https://github.com/projectdiscovery/nuclei) is a very powerful scanner that has a lot of community contributed checkers that are safe to use for checking if a host is vulnerable to a CVE without breaking the law. These community Nuclei templates can be found in https://github.com/projectdiscovery/nuclei-templates. 

**MAKE SURE YOU READ AND UNDERSTAND THE TEMPLATE BEFORE USE.**

To use a nuclei template to scan a list of hosts, put IP addresses / domain names in a text file (one line each) and specify the template path using `-t`:

`nuclei -list ips.txt -t ./templates/CVE-2019-0230.yaml -json-export output.json`


**DO NOT USE MULTIPLE TEMPLATES AT THE SAME TIME, AND ESPECIALLY DO NOT SCAN HOSTS WITH ALL TEMPLATES.**

Nuclei is a very fast scanner, and it can cause availability impact to the targets if you scan aggressively, as well as trigger noisy and unnecessary alerts. Only use Nuclei to validate one vulnerability on a group of hosts at a time.

### Writing your own checker

If you have a good technical understanding of the vulnerability, and a public PoC is not available, you can start to write your own. Usually, web-based exploits that are unauthenticated and are one-shot requests are easy to write. Again, you just want to determine if the host is vulnerable, but not actually exploit it.

This is an example script using Python [requests](https://pypi.org/project/requests/) to check for a .git repository exposure of a URL:

```py
import sys
import requests

url = sys.argv[1]

# use a user agent to denote yourself as a security researcher
headers = {"User-Agent": "Security Check Script"}

r = requests.get(url + "/.git/config", headers=headers)
print('status:', r.status_code)
if r.status_code == 200 and ("git" in r.text or "branch" in r.text):
	print(f"[VULN] URL {url + '/.git/config'} likely contains git config")
else:
	print(f"No problems found for {url}")

```

This script does not break the law because it does not constitute any authorized access, modification or impairment of the target. (Also, it's basically just web browsing)

Alternatively, you can also write your own Nuclei template and run that instead. See ["Introduction to Nuclei Templates"](https://docs.projectdiscovery.io/templates/introduction) for more information, and see DirectCyber's own checker scripts and nuclei-templates that are carefully made to be as non-intrusive as possible https://github.com/directcyber/checkers


## Host to org correlation

Once you identify vulnerable hosts on Shodan, you should use Shodan's API to get the results. 

Use the shodan CLI (`pip3 install shodan`) to count the result before you download it, so that you know if you have enough credit.

You can get statistics based on different facets (like as `port`, `country`, `org` and `product`) by running `shodan stats` with your query

- with default facets

```
$ shodan stats '.org.au'
Top 3 Results for Facet: country
AU                                    14
US                                     7
NZ                                     1

Top 10 Results for Facet: org
NetActuate, Inc                        6
Amazon Corporate Services Pty Ltd           5
Mammoth Media Pty Ltd                  3
SYNERGY WHOLESALE PTY LTD              2
Amazon.com, Inc.                       1
Hostopia Australia Pty Ltd             1
Linode                                 1
OVH Singapore PTE. LTD                 1
Telstra Internet                       1
University of Otago                    1
```

- with specific facets

```
$ shodan stats --facets port,product '.org.au'
Top 4 Results for Facet: product
Postfix smtpd                          6
Apache httpd                           4
nginx                                  3
ProFTPD                                1

Top 7 Results for Facet: port
80                                     7
443                                    5
25                                     3
21                                     2
465                                    2
587                                    2
53                                     1
```

You can count the total number of results by using `shodan count 'your query'`

Running stats or count does not consume query credits. You can get your remaining credits this month by running `shodan info`

Divide the count of results by 100 to get how much credit you'd spend and if you have enough, then, you can use this [script](https://github.com/directcyber/scripts/blob/main/shodan_query_get_all.py) to get all results in JSON format for ease of use.

`export SHODAN_KEY=your_shodan_key_here`

`./shodan_query_get_all.py 'query here'`

The results will be written to a new `.jsonl` file (one line each result).

You can then use `jq` to get the IP and details of the hosts into tsv format, and de-duplicate:

`jq  -r "[.ip_str , .org, .asn,  .ssl.cert.subject.CN, .domains[0], .domains[1], .domains[2]] | @tsv" < *.jsonl | sort -u`

The org and asn fields are the network names of the hosting provider (unless the organization has its own ASN); the subject CN of any encryption certificates (this could be self signed, so watch out for fakes and honeypots) and domains extracted by shodan via forward or reverse DNS lookups tell us what the domain of the organzation could be.

You can lookup those domains in a search engine to determine the nature of the organization and what they do for prioritization of alerts.

## Finding organizational contacts

### security.txt

[RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) is the standard for `security.txt`, which is a file at the root of a website (e.g. https://directcyber.com.au/security.txt) that contains contact information for reporting security vulnerabilities.

### WHOIS and RDAP

WHOIS lookups of the domain (run `whois example.com`) can be used to find potential details of the organization and who to contact, but information could be redacted there.

Similar details can be found on a more modern system called RDAP (https://client.rdap.org/)

### LinkedIn

LinkedIn sucks but if you have an account, you can lookup people on LinkedIn once you've found the organization. Focus on IT and security roles and see if you can connect with them or guess their email address based on known email formats for that organization (like `first.last@example.com` or `flast@example.com` or `firstname@example.com`)

### phonebook.cz

If you have a [IntelX](https://intelx.io/) account (or sign up for one), you can use https://phonebook.cz/ to lookup emails for a specific domain. This will give you a good idea of what email formats look like for the organization.


## Sending notifications


If you can find a trusted back-channel contact (such as Direct Messaging someone who works there, or someone who works at their IT MSP or Security MSSP, or someone who knows someone..) to send the organization a tip, then utilize that. Send the notification on multiple channels if possible to amplify trust and to sound less scammy (for example, through both email and phone call, or through both back-channel and email).

The highest fidelity notifications possible is in person. You could print out the vulnerability alert, such as an ACSC cyber.gov.au issued alert and write down details of their vulnerable hosts, then drop it at the organization's front desk along with a treat for their IT and security teams to incentivize patching (like [cybermuffins](https://cybermuffins.org)).




