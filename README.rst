EroSmb
============

.. figure:: https://raw.githubusercontent.com/viktor02/EroSmb/master/img/logo.png

EroSmb is a fast smb network scanner. You can easily enumerate windows machines in your local network using this tool.

Disclaimer
----------

**Do not to use this product for any illegal purpose, otherwise you may be subject to prosecutions under applicable laws.**

**Make sure you have permission to scan your network.**

What is it
------------
This program shows you which machines are currently online in your network, their OS version, arch and IP.


Installation
------------

Clone the repository and run ::

  git checkout inputfile-and-progressbar
  pip install .


FAQ
------------
    - Why do I need this utility if metasploit/smb_version and nmap already exists?

Metasploit smb_version makes ping requests and if the target does not respond to them 
(and in Windows this is the *standard firewall policy*) 
skips and does not scan the target.

Nmap OS Detection sends special packets to the tcp/ip stack and parses the response for matches. 
This is universal, but unreliable and slow. 

EroSmb only scan two ports (139 and 445) and if the connection is successful, it asks about the SMB protocol version of the server and the OS version. This is fast and reliable way. 

    - Can I scan entire Internet?

No, because on every IP address programs make a new thread and you just might not have enough memory and processor time. 
Also scanning other people's networks without permission may be illegal in your country.
