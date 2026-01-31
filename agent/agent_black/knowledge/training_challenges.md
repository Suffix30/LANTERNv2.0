# Training Challenges - Figure It Out

## Philosophy
You are given TASKS, not ANSWERS. Investigate. Reason. Discover.
When you find something, document it as a TROPHY.

---

# METASPLOITABLE2 CHALLENGES

Target: <YOUR_TARGET_IP> (e.g., Metasploitable at 192.168.56.101)
OS: Unknown Linux (discover it yourself)

## PHASE 1: Reconnaissance
- [ ] What OS and kernel version is running?
- [ ] How many ports are open?
- [ ] What services are running on each port?
- [ ] What versions are those services?

## PHASE 2: Initial Access
Find a way in. Multiple paths exist.
- [ ] Can you get a shell without credentials?
- [ ] Are there any backdoors?
- [ ] Are there default credentials anywhere?
- [ ] Any vulnerable service versions?

## PHASE 3: Credential Harvesting
Once you have access:
- [ ] Find all user accounts
- [ ] Find all password hashes
- [ ] Can you crack any hashes?
- [ ] Are there passwords in config files?
- [ ] Are there SSH keys you can steal?

## PHASE 4: Service Exploitation
Each service is a puzzle:
- [ ] FTP - What version? Any known vulns?
- [ ] SSH - Weak credentials?
- [ ] Web - What applications are running? Vulns?
- [ ] Database - Can you connect? Dump data?
- [ ] SMB - Version? Exploits?
- [ ] Other ports - What are they? Research each one.

## PHASE 5: Privilege Escalation
If you don't have root:
- [ ] What user are you?
- [ ] What can you sudo?
- [ ] Any SUID binaries?
- [ ] Kernel exploits?
- [ ] Cron jobs?

## PHASE 6: Data Extraction
What valuable data exists?
- [ ] Database contents
- [ ] User files
- [ ] Credentials for other systems
- [ ] SSH keys
- [ ] Bash history

## PHASE 7: Lateral Movement
- [ ] Are there other hosts on the network?
- [ ] Can you use found credentials elsewhere?
- [ ] NFS? SMB shares?

---

# TROPHY TEMPLATE

When you find something, record it:

```
TROPHY: [Name]
Category: [Shell/Credential/Data/Exploit]
How Found: [Your methodology]
Value: [What this gives you]
```

---

# HINTS (Only if stuck for 5+ minutes)

## Hint Level 1 - General Direction
- Check for backdoors on unusual ports
- Old software has known vulnerabilities
- Default credentials are common
- Some services allow command execution

## Hint Level 2 - More Specific
- Port 1524 is suspicious
- FTP version matters a lot
- IRC servers can be backdoored
- R-services trust too much

## Hint Level 3 - Research Terms
- Google: "[service] [version] exploit"
- Check Exploit-DB
- Check Metasploit modules
- CVE database

---

# RULES FOR LEARNING

1. TRY FIRST - Don't look up answers immediately
2. DOCUMENT EVERYTHING - Your methodology matters
3. UNDERSTAND WHY - Don't just run commands blindly
4. CHAIN ATTACKS - One finding leads to another
5. BE THOROUGH - Don't stop at first shell

---

# SUCCESS CRITERIA

Metasploitable2 is "complete" when you have:
- [ ] At least 3 different shells
- [ ] Root access
- [ ] All password hashes
- [ ] At least 2 cracked passwords
- [ ] Database dump
- [ ] Understanding of each vulnerability you exploited
