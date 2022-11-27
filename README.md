# Responding-to-a-Nation-State-Cyber-Attack
![Flags](https://video.udacity-data.com/topher/2020/September/5f594254_image4/image4.png)
## Scenario

### South Udan and North Udan

**South Udan** is a small island nation that is a peaceful and technologically advanced nation! Because of its small size, the country believes in efficiently using its land and natural resources. Their scientists recently came up with a novel and cleaner means of performing nuclear fission of an element called Tridanium. This allows them to generate 100 times more energy and drastically reduce nuclear waste, thus making it the most efficient and clean way to generate electricity. This enabled them to generate cleaner and cheaper electricity, thus improving the lives of their citizens.

**North Udan** was extremely jealous of the progress of their neighbors. They still rely on using coal and other fossil fuels which are known to speed up global warming. In order to disrupt South Udan program, the government of North Udan decides to launch a cyberattack on South Udan Tridanium processing plant and disrupt its operation.

**The National Peace Agency of North Udan**, which is an undercover organization that runs the nation-state espionage program, launches an attack during a national holiday in South Udan (the holiday marks 50 years of border separation of the two nations). They manage to compromise a linux server which serves as a jump host to connect the Tridanium processing plant to the internet. They attempted to brute force the password of an employee account which triggered a security alarm. You have been immediately called onboard to respond to the security alarm and contain the ongoing cyberattack. You will begin the investigation from the compromised jump box to detect and mitigate the threats. Since it's a mission-critical server, you are also tasked with immediately hardening the server to proactively defeat future attacks from North Udan.

## Section 1: Threat Detection
![...](https://video.udacity-data.com/topher/2020/July/5f0e1bf3_noun-cyber-attack-3315528/noun-cyber-attack-3315528.png)


### Task 1: ClamAV scan

As a first threat detection measure, you will have to perform an antivirus scan on the system to determine the malware files planted by the National Peace Agency on the processing plant’s server. Launch ClamAV malware scanner and perform a scan on the ‘Downloads’ directory (/home/ubuntu/Downloads/). Report all detections in the clamAV_report.txt file.


### Task 2: Suspicious File Identification

You know that the National Peace Agency has an advanced infiltration group. As a curious investigator, you still want to explore other files available in the Downloads folder, despite the ClamAV scan detecting some files as malware. Can you spot one more suspicious file which should have been a cause of infection but managed to defeat your ClamAV scan? Find this filename and the embedded callout URLs hardcoded in this file. This callout domain is the Command & control server of the National Peace agency. Report this finding in the file suspicious_file_report.txt.

### Task 3: Yara Rule Creation

Once you have ensured the presence of a unique malware file that could not be detected through ClamAV scan, you also want to ensure that there is a signature or rule in place so that you can scan your other servers for the presence of the same file. Create a Yara rule file named unknown_threat.yara which can be compiled with ClamAV to detect the unique malware you have identified in the task above.

## Section 2: Threat Mitigation
![...](https://video.udacity-data.com/topher/2020/July/5f0e394a_noun-cyber-security-2483019/noun-cyber-security-2483019.png)

### Task 1: Implement HIDS

The first security alarm about the ongoing cyberattack came from the Host-Based Intrusion Detection System is about multiple failed login attempts from a foreign IP address. Launch the host IDS and analyze the logs and events captured in the system. To verify that the IDS is up and working, try connecting to the virtual machine via SSH and notice the new login entry created in the IDS web UI. Take a snapshot of the newly created log lines and name it succesful_ssh_logon.png. This will ensure that the IDS system is working as expected and capturing logs in real-time. Once you have taken the snapshot, upload it to the /starter/section_2/ directory in Github.

### Task 2: Locate Suspicious IP

Once you have verified that the IDS is working fine, you are now required to collect the next indicator of compromise(IoC), which is the IP address that attempted to break into the system. This IoC will prove significant in attributing the threat actors behind the cyber attack. You were told that the initial security alarm consisted of multiple failed login attempts on the jump host server. To verify that, filter the IDS alerts to specifically look for failed logins followed by a successful one. To further disrupt the network after a successful login, the attackers execute a command to elevate their privilege to system root. Your goal is to identify that IP address which made the logon attempts and then performed privilege escalation to the ‘root’ user. Report the IP address in the attacker_IP.txt file.

Since the attack happened in the year 2020, and that's when we captured the OVA image. Make sure that you are looking for the logs during that time frame.

### Task 3: IPtables Rule

Once you have identified the attacking IP address, you are now required to create an IPtables rule to make sure that any SSH connection requests from this host are blocked in the future. Hopefully, this will stop this agent from the so-called National Peace Agency from connecting again. Report your IP table rule in the Iptable_rule.txt that will deny SSH access to the attacking IP.

### Task 4: Detect Backdoor Username, Process & Port

Once the attackers managed to break into the system, they created a backdoor username and launched a process that allows them to log in through a non-standard port number. This is a common tactic implemented by nation-state actors to ensure continuous access to the compromised system. Your goal is:

Identify the rogue username: Analyze the logs to find the rogue user added to the system. Once you have the username, you'd want to view the /var/log/auth.log to check for the authorization events. Next, fetch all processes that are currently running for that user.
Locate the malicious process: Consider that the newly created rogue user has sufficient permissions to use the root credentials to run the backdoor process. Therefore, you will not find a process running in the name of the rogue user. Instead, the backdoor process will be running as root. Analyze the currently running processes to find that suspicious process.

IP address/port: Once you have the process name with you, find the "non-standard" port it is listening on.
Both IDS logs, as well as system commands, can be used to perform this task. Report these three details, along with a justification, in the backdoor_details.txt file.

Delete the rogue username and kill the backdoor process to remove the persistence created by the attackers.

### Task 5: Disable SSH Root Access

So far, we have figured out that the attack was carried out through brute-forcing ssh login credentials. Can you update the SSH configuration file to ensure that root login through SSH is never allowed, even if the correct set of credentials have been used? Report your changes by modifying the respective configuration entry and providing a snapshot of the change you have made. Name the file as remote_config_change.jpg.

As an optional stand out task, you can also provide a set of best practice recommendations to the senior leadership about further securing the remote login process and password management in the organization. While you appreciate the job security, you also don't appreciate the National Peace Agency making you come in on your day off. Provide your recommendation in the additional_remote_security_recommendations.txt file.

## Section 3: System Hardening for Enhanced Security
![...](https://video.udacity-data.com/topher/2020/July/5f0e39ad_noun-firewall-3427780/noun-firewall-3427780.png)

### Task 1: OpenVAS Scan

Now that the cyber-attack has been successfully contained, you are also tasked with further hardening the jump host server. As a first step, perform an OpenVAS vulnerability scan on the system and provide a snapshot of the vulnerabilities identified by the scan. Name the snapshot asopenvas_vulnerability_report.png.

### Task 2: Patching Apache

Once you have provided your report on the existing vulnerabilities on the system, you notice that the jump host is also running an Apache HTTP server which can be accessed from the internet and can serve as an attack point in future incidents. To harden the Apache server, you must remove the version banner from being publicly visible. This would make it difficult for an attacker to perform reconnaissance on the server and launch attacks. Your goal is to identify and report the current Apache httpd server version and then the configuration change required to prevent the version number benign publicly accessible. Report both these details in the filename apache_version_patching.txt.

### Task 3: De-Privilege Apache Account

As a final task of hardening the system, you want to ensure that Apache always runs as a low privileged user with restricted system access. To do that, create a new user group called “apache-group” and a new user account called apache-user. Can you list the configuration changes you’ll have to make sure that Apache launches with this new user account and group name? Provide your response in apache_user_account.txt.

**Optional Stand Out Task:**

The head of security for South Udan is grateful to you for your services. They want to award you with a commendation, and you are asked to prepare an “Executive Summary” of the entire investigation and changes you have made to contain the threat. This executive summary will be used to brief the head of South Udan about the incident. You can provide your summary in the form of a PDF, Word or text file, depending on whether you want to use only text or add images. Name the file as “Executive_summary” and upload it to the section 3 directory itself.
