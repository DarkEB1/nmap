
Basic Syntax – nmap [ <Scan Type> ...] [ <Options> ] { <targe specification> }

You can type nmap -h for the help menu, there you can see all of the scan types and options.


  
EXAMPLES:
  nmap -v -A scanme.nmap.org
  nmap -v -sn 192.168.0.0/16 10.0.0.0/8
  nmap -v -iR 10000 -Pn -p 80
SEE THE MAN PAGE (http://nmap.org/book/man.html) FOR MORE OPTIONS AND EXAMPLES


Now you know what is Nmap Let’s talk about NSE scripts.

What is NSE Scripts?
The Nmap Scripting Engine (NSE) is one of Nmap’s most powerful and flexible features. It allows users to write (and share) simple scripts to automate a wide variety of networking tasks. Those scripts are then executed in parallel with the speed and efficiency you expect from Nmap.

    Now, What are some good NSE scripts you must use while looking for vulnerabilities or even recon.
    
    1. dns-brute.nse
    Attempts to enumerate DNS hostnames by brute force guessing of common subdomains.

    The dns-brute script tries to find as many subdomains as the host is being tested using the most frequently used subdomain names.

(Result)

nmap -p 80 --script dns-brute.nse vulnweb.com
Starting Nmap 6.46 ( http://nmap.org ) at 2014-09-24 19:58 EST
Nmap scan report for vulnweb.com (176.28.50.165)
Host is up (0.34s latency).
rDNS record for 176.28.50.165: rs202995.rs.hosteurope.de
PORT   STATE SERVICE
80/tcp open  http
Host script results:
| dns-brute: 
|   DNS Brute-force hostnames: 
|     admin.vulnweb.com - 176.28.50.165
|     firewall.vulnweb.com - 176.28.50.165
|_    dev.vulnweb.com - 176.28.50.165
Nmap done: 1 IP address (1 host up) scanned in 28.41 seconds
2. http-enum.nse
Enumerates directories used by popular web applications and servers.

This parses a fingerprint file that’s similar in format to the Nikto Web application scanner. This script, however, takes it one step further by building in advanced pattern matching as well as having the ability to identify specific versions of Web applications.

(Result)
nmap.org
Nmap: the Network Mapper - Free Security Scanner
Nmap Free Security Scanner, Port Scanner, & Network Exploration Tool. Download open source software for Linux, Windows, UNIX, FreeBSD, etc.

nmap -sV --script=http-enum 
Interesting ports on test.skullsecurity.org (208.81.2.52): PORT   STATE SERVICE REASON 80/tcp open  http    syn-ack | http-enum: |   /icons/: Icons and images |   /images/: Icons and images |   /robots.txt: Robots file |   /sw/auth/login.aspx: Citrix WebTop |   /images/outlook.jpg: Outlook Web Access |   /nfservlets/servlet/SPSRouterServlet/: netForensics |_  /nfservlets/servlet/SPSRouterServlet/: netForensics
3. ssh-brute.nse
Simply putting this script Performs brute-force password guessing against ssh servers

(Result)

nmap -p 22 --script ssh-brute --script-args userdb=users.lst,passdb=pass.lst  --script-args ssh-brute.timeout=4s 
22/ssh open  ssh 
|  ssh-brute:
|  Accounts 
|  username:password 
|  Statistics 
|_   Performed 32 guesses in 25 seconds.
4. vulscan.nse
Vulscan is a Nmap Scripting Engine script which helps Nmap to find vulnerabilities on targets based on services and version detections to estimate vulnerabilities depending on the software listening on the target.

(Results)

# nmap -sV --script=vulscan/vulscan.nse google.com
Starting Nmap 7.70 ( https://nmap.org ) at 2020-01-29 20:14 -03
Nmap scan report for google.com (172.217.165.142)
Host is up (0.23s latency).
And this will give you all the possible vulnerability on the given domain.

5. smb-brute.nse
Attempts to guess username/password combinations over SMB, storing discovered combinations for use in other scripts. Every attempt will be made to get a valid list of users and to verify each username before actually using them.

This script just tries to brute force local account against smb services.

(results)

#nmap --script smb-brute.nse -p445 
sudo nmap -sU -sS --script smb-brute.nse -p U:137,T:139 
Host script results: 
| smb-brute: 
|   bad name:test => Valid credentials 
|   consoletest:test => Valid credentials, password must be changed at next logon 
|   guest: => Valid credentials, account disabled 
|   mixcase:BuTTeRfLY1 => Valid credentials 
|   test:password1 => Valid credentials, account expired 
|   this:password => Valid credentials, account cannot log in at current time 
|   thisisaverylong:password => Valid credentials 
|   thisisaverylongname:password => Valid credentials 
|   thisisaverylongnamev:password => Valid credentials 
|_  web:TeSt => Valid credentials, account disabled
So, These are some NSE scripts that are widely used by the community.
nmap.org
Nmap: the Network Mapper - Free Security Scanner
Nmap Free Security Scanner, Port Scanner, & Network Exploration Tool. Download open source software for Linux, Windows, UNIX, FreeBSD, etc.
    
Help menu

    Nmap 5.51 ( http://nmap.org )
    Usage: nmap [Scan Type(s)] [Options] {target specification}
    TARGET SPECIFICATION:
      Can pass hostnames, IP addresses, networks, etc.
      Ex: scanme.nmap.org, 192.168.0.1; 10.0.0-255.1-254
      -iL : Input from list of hosts/networks
      -iR : Choose random targets
      --exclude <host1[,host2][,host3],...>: Exclude hosts/networks
      --excludefile : Exclude list from file

    HOST DISCOVERY:
      -sL: List Scan - simply list targets to scan
      -sn: Ping Scan - disable port scan
      -Pn: Treat all hosts as online -- skip host discovery
      -PS/PA/PU/PY[portlist]: TCP SYN/ACK, UDP or SCTP discovery to given ports
      -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
      -PO[protocol list]: IP Protocol Ping
      -n/-R: Never do DNS resolution/Always resolve [default: sometimes]
      --dns-servers <serv1[,serv2],...>: Specify custom DNS servers
      --system-dns: Use OS's DNS resolver
      --traceroute: Trace hop path to each host

    SCAN TECHNIQUES:
      -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
      -sU: UDP Scan
      -sN/sF/sX: TCP Null, FIN, and Xmas scans
      --scanflags : Customize TCP scan flags
      -sI : Idle scan
      -sY/sZ: SCTP INIT/COOKIE-ECHO scans
      -sO: IP protocol scan
      -b : FTP bounce scan

    PORT SPECIFICATION AND SCAN ORDER:
      -p : Only scan specified ports
        Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
      -F: Fast mode - Scan fewer ports than the default scan
      -r: Scan ports consecutively - don't randomize
      --top-ports : Scan  most common ports
      --port-ratio : Scan ports more common than 

    SERVICE/VERSION DETECTION:
      -sV: Probe open ports to determine service/version info
      --version-intensity : Set from 0 (light) to 9 (try all probes)
      --version-light: Limit to most likely probes (intensity 2)
      --version-all: Try every single probe (intensity 9)
      --version-trace: Show detailed version scan activity (for debugging)

    SCRIPT SCAN:
      -sC: equivalent to --script=default
      --script=:  is a comma separated list of
               directories, script-files or script-categories
      --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts
      --script-trace: Show all data sent and received
      --script-updatedb: Update the script database.

    OS DETECTION:
      -O: Enable OS detection
      --osscan-limit: Limit OS detection to promising targets
      --osscan-guess: Guess OS more aggressively

    TIMING AND PERFORMANCE:
      Options which take  are in seconds, or append 'ms' (milliseconds),
      's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
      -T<0-5>: Set timing template (higher is faster)
      --min-hostgroup/max-hostgroup : Parallel host scan group sizes
      --min-parallelism/max-parallelism : Probe parallelization
      --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout : Specifies
          probe round trip time.
      --max-retries : Caps number of port scan probe retransmissions.
      --host-timeout : Give up on target after this long
      --scan-delay/--max-scan-delay : Adjust delay between probes
      --min-rate : Send packets no slower than  per second
      --max-rate : Send packets no faster than  per second

    FIREWALL/IDS EVASION AND SPOOFING:
      -f; --mtu : fragment packets (optionally w/given MTU)
      -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys
      -S : Spoof source address
      -e : Use specified interface
      -g/--source-port : Use given port number
      --data-length : Append random data to sent packets
      --ip-options : Send packets with specified ip options
      --ttl : Set IP time-to-live field
      --spoof-mac : Spoof your MAC address
      --badsum: Send packets with a bogus TCP/UDP/SCTP checksum

    OUTPUT:
      -oN/-oX/-oS/-oG : Output scan in normal, XML, s|: Output in the three major formats at once
      -v: Increase verbosity level (use -vv or more for greater effect)
      -d: Increase debugging level (use -dd or more for greater effect)
      --reason: Display the reason a port is in a particular state
    nmap.org
    Nmap: the Network Mapper - Free Security Scanner
    Nmap Free Security Scanner, Port Scanner, & Network Exploration Tool. Download open source software for Linux, Windows, UNIX, FreeBSD, etc.


    --open: Only show open (or possibly open) ports
      --packet-trace: Show all packets sent and received
      --iflist: Print host interfaces and routes (for debugging)
      --log-errors: Log errors/warnings to the normal-format output file
      --append-output: Append to rather than clobber specified output files
      --resume : Resume an aborted scan
      --stylesheet <path/URL>: XSL stylesheet to transform XML output to HTML
      --webxml: Reference stylesheet from Nmap.Org for more portable XML
      --no-stylesheet: Prevent associating of XSL stylesheet w/XML output

    MISC:
    -6: Enable IPv6 scanning
    -A: Enable OS detection, version detection, script scanning, and traceroute
    --datadir : Specify custom Nmap data file location
    --send-eth/--send-ip: Send using raw ethernet frames or IP packets
    --privileged: Assume that the user is fully privileged
    --unprivileged: Assume the user lacks raw socket privileges
    -V: Print version number
    -h: Print this help summary page.
