# metasploit-modules
A repo where I lob metasploit modules

# Git-Enum
This should go into "/modules/post/linux/gather".
Run this on a compromised Linux server to enumerate details from Git configuration files.

This will find: credentials, personal access tokens, and SSH keys.
It will also: list the remote URL for every ".git/config" file on the affected host. Useful to find internal git servers and possibly to find private repositories hosted on GitHub.com
