#!/bin/bash
#A script to enumerate local information from a Linux host
v="version 0.8"
#@rebootuser

printf "\n"
#help function
usage () 
{ 
    printf "#########################################################\n"
    printf "# Local Linux Enumeration & Privilege Escalation Script #\n"
    printf "#########################################################\n"
    printf "# www.rebootuser.com | @rebootuser \n"
    printf "# %s\n" "$v"
    printf "# Example: ./LinEnum.sh -k keyword -r report -e /tmp/ -t \n"
    printf "\n"
    printf "OPTIONS:\n"
    printf "-k    Enter keyword\n"
    printf "-e    Enter export location\n"
    printf "-t    Include thorough (lengthy) tests\n"
    printf "-r    Enter report name\n"
    printf "-h    Displays this help text\n"
    printf "\n"
    printf "Running with no options = limited scans/no output file\n"
    printf "#########################################################\n"
}

header()
{
    printf "\n#########################################################\n"
    printf "# Local Linux Enumeration & Privilege Escalation Script #\n"
    printf "#########################################################\n"
    printf "# www.rebootuser.com\n"
    printf "# %s\n" "$version"
}

debug_info()
{
    printf "[-] Debug Info\n" 

    [[ -z "${keyword}" ]] || printf "[+] Searching for the keyword %s in conf, php, ini and log files\n" "$keyword"
    [[ -z "${report}" ]] || printf "[+] Report name = %s\n" "$report"
    [[ -z "${export}" ]] || printf "[+] Export location = %s\n" "$export"
    [[ -z "${thorough}" ]] || printf "[+] Thorough tests = Enabled\n" && printf "[+] Thorough tests = Disabled (SUID/GUID checks will not be perfomed!)\n"

    # -Mav
    #sleep 2

    if [ "$export" ]; then
        # -Mav
        #mkdir $export 2>/dev/null
        #format=$export/ex
        #mkdir $format 2>/dev/null
        :
    fi

    # -Mav
    #who=`whoami` 2>/dev/null 

}
printf "\nScan started at:%s\n\n" "$(date)"

system_info()
{
    printf "### SYSTEM ##############################################\n"
    #basic kernel info
    unameinfo=$(uname -a 2>/dev/null) && printf "[-] Kernel information:\n%s\n\n" "$unameinfo"
    procver=$(cat /proc/version 2>/dev/null) && printf "[-] Kernel information (continued):\n%s\n\n" "$procver"
    #search all *-release files for version info
    release=$(cat /etc/*-release 2>/dev/null) && printf "[-] Specific release information:\n%s\n\n" "$release"
    #target hostname info
    hostnamed=$(hostname 2>/dev/null) && printf "[-] Hostname:\n%s \n\n" "$hostnamed"
}

user_info()
{
    printf "### USER/GROUP ##########################################\n"

    #current user details
    currusr=$(id 2>/dev/null) && \
        printf "[-] Current user/group info:\n%s\n\n" "$currusr"

    #last logged on user information
    lastlogedonusrs=$(lastlog 2>/dev/null |grep -v "Never" 2>/dev/null) && \
        printf "[-] Users that have previously logged onto the system:\n%s\n\n" "$lastlogedonusrs"

    #who else is logged on
    loggedonusrs=$(w 2>/dev/null) && \
        printf "[-] Who else is logged on:\n%s\n\n" "$loggedonusrs"

    #lists all id's and respective group(s)
    grpinfo=$(for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null) && \
        printf "[-] Group memberships:\n%s\n\n" "$grpinfo"

    #added by phackt - look for adm group (thanks patrick)
    adm_users=$(echo -e "$grpinfo" | grep "(adm)") && \
        printf "[-] It looks like we have some admin users:\n%s\n\n" "$adm_users"

    #checks to see if any hashes are stored in /etc/passwd (depreciated  *nix storage method)
    hashesinpasswd=$(grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null) && \
        printf "[+] It looks like we have password hashes in /etc/passwd.\n%s\n\n" "$hashesinpasswd"

    #contents of /etc/passwd
    readpasswd=$(cat /etc/passwd 2>/dev/null) && \
        printf "[-] Contents of /etc/passwd:\n%s\n\n" "$readpasswd"

    if [ "$export" ] && [ "$readpasswd" ]; then
        mkdir $format/etc-export/ 2>/dev/null
        cp /etc/passwd $format/etc-export/passwd 2>/dev/null
    fi

    #checks to see if the shadow file can be read
    readshadow=$(cat /etc/shadow 2>/dev/null) && \
        printf "[+] We can read the shadow file.\n%s\n\n" "$readshadow"

    if [ "$export" ] && [ "$readshadow" ]; then
        mkdir $format/etc-export/ 2>/dev/null
        cp /etc/shadow $format/etc-export/shadow 2>/dev/null
    else 
        :
    fi

    #checks to see if /etc/master.passwd can be read - BSD 'shadow' variant
    readmasterpasswd=$(cat /etc/master.passwd 2>/dev/null) && \
        printf "[+] We can read the master.passwd file.\n%s\n\n" "$readmasterpasswd"

    if [ "$export" ] && [ "$readmasterpasswd" ]; then
        mkdir $format/etc-export/ 2>/dev/null
        cp /etc/master.passwd $format/etc-export/master.passwd 2>/dev/null
    else 
        :
    fi

    #all root accounts (uid 0)
    superman=$(grep -v -E "^#" /etc/passwd 2>/dev/null| awk -F: '$3 == 0 { print $1}' 2>/dev/null) && \
        printf "[-] Super user account(s):\n%s\n\n" "$superman"

    #pull out vital sudoers info
    sudoers=$(grep -v -e '^$' /etc/sudoers 2>/dev/null |grep -v "#" 2>/dev/null) && \
        printf "[-] Sudoers configuration (condensed):\n%s\n\n" "$sudoers"

    if [ "$export" ] && [ "$sudoers" ]; then
        mkdir $format/etc-export/ 2>/dev/null
        cp /etc/sudoers $format/etc-export/sudoers 2>/dev/null
    else 
        :
    fi

    #can we sudo without supplying a password
    sudoperms=$(echo '' | sudo -S -l 2>/dev/null) && \
        printf "[+] We can sudo without supplying a password.\n%s\n\n" "$sudoperms"

    #known 'good' breakout binaries
    sudopwnage=$(echo '' | sudo -S -l 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'emacs'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb' | xargs -r ls -la 2>/dev/null) && \
        printf "[+] Possible sudo pwnage.\n%s\n\n" "$sudopwnage"

    #who has sudoed in the past
    whohasbeensudo=$(find /home -name .sudo_as_admin_successful 2>/dev/null) && \
        printf "[-] Accounts that have recently used sudo:\n%s\n\n" "$whohasbeensudo"

    #checks to see if roots home directory is accessible
    rthmdir=$(ls -ahl /root/ 2>/dev/null) && \
        printf "[+] We can read root's home directory.\n%s\n\n" "$rthmdir"

    #displays /home directory permissions - check if any are lax
    homedirperms=$(ls -ahl /home/ 2>/dev/null) && \
        printf "[-] Are permissions on /home directories lax:\n%s\n\n" "$homedirperms"

    #looks for files we can write to that don't belong to us
    if [ "$thorough" = "1" ]; then
        grfilesall=$(find / -writable ! -user \`whoami\` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null) && \
            printf "[-] Files not owned by user but writable by group:\n%s\n\n" "$grfilesall"
    fi

    #looks for files that belong to us
    if [ "$thorough" = "1" ]; then
        ourfilesall=$(find / -user \`whoami\` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null) && \
            printf "[-] Files owned by our user:\n%s\n\n" "$ourfilesall"
    fi

    #looks for hidden files
    if [ "$thorough" = "1" ]; then
        hiddenfiles=$(find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null) && \
            printf "[-] Hidden files:\n%s\n\n" "$hiddenfiles"
    fi

    #looks for world-reabable files within /home - depending on number of /home dirs & files, this can take some time so is only 'activated' with thorough scanning switch
    if [ "$thorough" = "1" ]; then
        wrfileshm=$(find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null) && \
            printf "[-] World-readable files within /home:\n%s\n\n" "$wrfileshm"
    fi

    if [ "$thorough" = "1" ]; then
        if [ "$export" ] && [ "$wrfileshm" ]; then
            mkdir $format/wr-files/ 2>/dev/null
            for i in $wrfileshm; do cp --parents $i $format/wr-files/ ; done 2>/dev/null
        fi
    fi

    #lists current user's home directory contents
    if [ "$thorough" = "1" ]; then
        homedircontents=$(ls -ahl ~ 2>/dev/null) && \
            printf "[-] Home directory contents:\n%s\n\n" "$homedircontents"
    fi

    #checks for if various ssh files are accessible - this can take some time so is only 'activated' with thorough scanning switch
    if [ "$thorough" = "1" ]; then
        sshfiles=$(find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} 2>/dev/null \;) && \
            printf "[-] SSH keys/host information found in the following locations:\n%s\n\n" "$sshfiles"
    fi

    if [ "$thorough" = "1" ]; then
        if [ "$export" ] && [ "$sshfiles" ]; then
            mkdir $format/ssh-files/ 2>/dev/null
            for i in $sshfiles; do cp --parents $i $format/ssh-files/; done 2>/dev/null
        fi
    fi

    #is root permitted to login via ssh
    sshrootlogin=$(grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk '{print  $2}') && \
        printf "[-] Root is allowed to login via SSH: %s\n\n" "$(grep 'PermitRootLogin ' /etc/ssh/sshd_config 2>/dev/null | grep -v '#')"
}

environmental_info()
{
    printf "### ENVIRONMENTAL #######################################\n"

    #env information
    envinfo=$(env 2>/dev/null | grep -v 'LS_COLORS' 2>/dev/null) && \
        printf "[-] Environment information:\n%s\n\n" "$envinfo"

    #check if selinux is enabled
    sestatus=$(sestatus 2>/dev/null) && \
        printf "[-] SELinux seems to be present:\n%s\n\n" "$sestatus"

    #phackt

    #current path configuration
    pathinfo=$(echo $PATH 2>/dev/null) && \
        printf "[-] Path information:\n%s\n\n" "$pathinfo"

    #lists available shells
    shellinfo=$(cat /etc/shells 2>/dev/null) && \
        printf "[-] Available shells:\n%s\n\n" "$shellinfo"

    #current umask value with both octal and symbolic output
    umaskvalue=$(umask -S 2>/dev/null & umask 2>/dev/null) && \
        printf "[-] Current umask value:\n%s\n\n" "$umaskvalue"

    #umask value as in /etc/login.defs
    umaskdef=$(grep -i "^UMASK" /etc/login.defs 2>/dev/null) && \
        printf "[-] umask value as specified in /etc/login.defs:\n%s\n\n" "$umaskdef"

    #password policy information as stored in /etc/login.defs
    logindefs=$(grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null) && \
        printf "[-] Password and storage information:\n%s\n\n" "$logindefs"

    if [ "$export" ] && [ "$logindefs" ]; then
        mkdir $format/etc-export/ 2>/dev/null
        cp /etc/login.defs $format/etc-export/login.defs 2>/dev/null
    fi
}

job_info()
{
    printf "### JOBS/TASKS ##########################################\n"

    #are there any cron jobs configured
    cronjobs=$(ls -la /etc/cron* 2>/dev/null) && \
        printf "[-] Cron jobs:\n%s\n\n" "$cronjobs"

    #can we manipulate these jobs in any way
    cronjobwwperms=$(find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2>/dev/null \;) && \
        printf "[+] World-writable cron jobs and file contents:\n%s\n\n" "$cronjobwwperms"

    #contab contents
    crontabvalue=$(cat /etc/crontab 2>/dev/null) && \
        printf "[-] Crontab contents:\n%s\n\n" "$crontabvalue"

    crontabvar=$(ls -la /var/spool/cron/crontabs 2>/dev/null) &&  \
        printf "[-] Anything interesting in /var/spool/cron/crontabs:\n%s\n\n" "$crontabvar"

    anacronjobs=$(ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null) && \
        printf "[-] Anacron jobs and associated file permissions:\n%s\n\n" "$anacronjobs"

    anacrontab=$(ls -la /var/spool/anacron 2>/dev/null) && \
        printf "[-] When were jobs last executed (/var/spool/anacron contents):\n%s\n\n" "$anacrontab"

    #pull out account names from /etc/passwd and see if any users have associated cronjobs (priv command)
    cronother=$(cut -d ":" -f 1 /etc/passwd | xargs -n1 crontab -l -u 2>/dev/null) && \
        printf "[-] Jobs held by all users:\n%s\n\n" "$cronother"

}

networking_info()
{
    printf "### NETWORKING  ##########################################\n"

    #nic information
    nicinfo=$(/sbin/ifconfig -a 2>/dev/null) && \
        printf "[-] Network and IP info:\n%s\n\n" "$nicinfo"

    #nic information (using ip)
    nicinfoip=$(/sbin/ip a 2>/dev/null) && \
        printf "[-] Network and IP info:\n%s\n\n" "$nicinfoip"

    arpinfo=$(arp -a 2>/dev/null) && \
        printf "[-] ARP history:\n%s\n\n" "$arpinfo"

    arpinfoip=$(ip n 2>/dev/null) && \
        printf "[-] ARP history:\n%s\n\n" "$arpinfoip"

    #dns settings
    nsinfo=$(grep "nameserver" /etc/resolv.conf 2>/dev/null) && \
        printf "[-] Nameserver(s):\n%s\n\n" "$nsinfo"

    nsinfosysd=$(systemd-resolve --status 2>/dev/null) && \
        printf "[-] Nameserver(s):\n%s\n\n" "$nsinfosysd"

    #default route configuration
    defroute=$(route 2>/dev/null | grep default) && \
        printf"[-] Default route:\n%s\n\n" "$defroute"

    #default route configuration
    defrouteip=$(ip r 2>/dev/null | grep default) && \
        printf "[-] Default route:\n%s\n\n" "$defrouteip"

    #listening TCP
    tcpservs=$(netstat -antp 2>/dev/null) && \
        printf "[-] Listening TCP:\n%s\n\n" "$tcpservs"

    tcpservsip=$(ss -t 2>/dev/null) && \
        printf "[-] Listening TCP:\n%s\n\n" "$tcpservsip"

    #listening UDP
    udpservs=$(netstat -anup 2>/dev/null) && \
        printf "[-] Listening UDP:\n%s\n\n" "$udpservs"

    udpservsip=$(ip -u 2>/dev/null) && \
        printf "[-] Listening UDP:\n%s\n\n" "$udpservsip"
}

services_info()
{
    printf "### SERVICES #############################################\n"

    #running processes
    psaux=$(ps aux 2>/dev/null) && \
        printf "[-] Running processes:\n%s\n\n" "$psaux"

    #lookup process binary path and permissisons
    procperm=$(ps aux 2>/dev/null | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++' 2>/dev/null) && \
        printf "[-] Process binaries and associated permissions (from above list):\n%s\n\n" "$procperm"

    if [ "$export" ] && [ "$procperm" ]; then
        procpermbase=$(ps aux 2>/dev/null | awk '{print $11}' | xargs -r ls 2>/dev/null | awk '!x[$0]++' 2>/dev/null)
        mkdir $format/ps-export/ 2>/dev/null
        for i in "$procpermbase"; do cp --parents $i $format/ps-export/; done 2>/dev/null
    fi

    #anything 'useful' in inetd.conf
    inetdread=$(cat /etc/inetd.conf 2>/dev/null) && \
        printf "[-] Contents of /etc/inetd.conf:\n%s\n\n" "$inetdread"

    if [ "$export" ] && [ "$inetdread" ]; then
        mkdir $format/etc-export/ 2>/dev/null
        cp /etc/inetd.conf $format/etc-export/inetd.conf 2>/dev/null
    fi

    #very 'rough' command to extract associated binaries from inetd.conf & show permisisons of each
    inetdbinperms=$(awk '{print $7}' /etc/inetd.conf 2>/dev/null |xargs -r ls -la 2>/dev/null) && \
        printf "[-] The related inetd binary permissions:\n%s\n\n" "$inetdbinperms"

    xinetdread=$(cat /etc/xinetd.conf 2>/dev/null) && \
        printf "[-] Contents of /etc/xinetd.conf:\n%s\n\n" "$xinetdread"

    if [ "$export" ] && [ "$xinetdread" ]; then
        mkdir $format/etc-export/ 2>/dev/null
        cp /etc/xinetd.conf $format/etc-export/xinetd.conf 2>/dev/null
    fi

    xinetdincd=$(grep "/etc/xinetd.d" /etc/xinetd.conf 2>/dev/null) && \
        printf "[-] /etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below:\n%s\n\n" "$(ls -la /etc/xinetd.d 2>/dev/null)"

    #very 'rough' command to extract associated binaries from xinetd.conf & show permisisons of each
    xinetdbinperms=$(awk '{print $7}' /etc/xinetd.conf 2>/dev/null |xargs -r ls -la 2>/dev/null) && \
        printf"[-] The related xinetd binary permissions:\n%s\n\n" "$xinetdbinperms"

    initdread=$(ls -la /etc/init.d 2>/dev/null) && \
        printf "[-] /etc/init.d/ binary permissions:\n%s\n\n" "$initdread"

    #init.d files NOT belonging to root!
    initdperms=$(find /etc/init.d/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null) && \
        printf "[-] /etc/init.d/ files not belonging to root:\n%s\n\n" "$initdperms"

    rcdread=$(ls -la /etc/rc.d/init.d 2>/dev/null) && \
        printf "[-] /etc/rc.d/init.d binary permissions:\n%s\n\n" "$rcdread"

    #init.d files NOT belonging to root!
    rcdperms=$(find /etc/rc.d/init.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null) && \
        printf "[-] /etc/rc.d/init.d files not belonging to root:\n%s\n\n" "$rcdperms"

    usrrcdread=$(ls -la /usr/local/etc/rc.d 2>/dev/null) && \
        printf "[-] /usr/local/etc/rc.d binary permissions:\n%s\n\n" "$usrrcdread"

    #rc.d files NOT belonging to root!
    usrrcdperms=$(find /usr/local/etc/rc.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null) && \
        printf "[-] /usr/local/etc/rc.d files not belonging to root:\n%s\n\n" "$usrrcdperms"
}

software_configs()
{
    printf "### SOFTWARE #############################################\n"

    #sudo version - check to see if there are any known vulnerabilities with this
    sudover=$(sudo -V 2>/dev/null| grep "Sudo version" 2>/dev/null) && \
        printf "[-] Sudo version:\n%s\n\n" "$sudover"

    #mysql details - if installed
    mysqlver=$(mysql --version 2>/dev/null) && \
        printf "[-] MYSQL version:\n%s\n\n" "$mysqlver"

    #checks to see if root/root will get us a connection
    mysqlconnect=$(mysqladmin -uroot -proot version 2>/dev/null) && \
        printf "[+] We can connect to the local MYSQL service with default root/root credentials.\n%s\n\n" "$mysqlconnect"

    #mysql version details
    mysqlconnectnopass=$(mysqladmin -uroot version 2>/dev/null) && \
        printf "[+] We can connect to the local MYSQL service as 'root' and without a password.\n%s\n\n" "$mysqlconnectnopass"

    #postgres details - if installed
    postgver=$(psql -V 2>/dev/null) && \
        printf "[-] Postgres version:\n%s\n\n" "$postgver"

    #checks to see if any postgres password exists and connects to DB 'template0' - following commands are a variant on this
    postcon1=$(psql -U postgres template0 -c 'select version()' 2>/dev/null | grep version) && \
        printf "[+] We can connect to Postgres DB 'template0' as user 'postgres' with no password\n%s\n\n" "$postcon1"

    postcon11=$(psql -U postgres template1 -c 'select version()' 2>/dev/null | grep version) && \
        printf "[+] We can connect to Postgres DB 'template1' as user 'postgres' with no password\n%s\n\n" "$postcon11"

    postcon2=$(psql -U pgsql template0 -c 'select version()' 2>/dev/null | grep version) && \
        printf "[+] We can connect to Postgres DB 'template0' as user 'psql' with no password\n%s\n\n" "$postcon2"

    postcon22=$(psql -U pgsql template1 -c 'select version()' 2>/dev/null | grep version) && \
        printf "[+] We can connect to Postgres DB 'template1' as user 'psql' with no password\n%s\n\n" "$postcon22"

    #apache details - if installed
    apachever=$(apache2 -v 2>/dev/null; httpd -v 2>/dev/null) && \
        printf "[-] Apache version:\n%s\n\n" "$apachever"

    #what account is apache running under
    apacheusr=$(grep -i 'user\|group' /etc/apache2/envvars 2>/dev/null |awk '{sub(/.*\export /,"")}1' 2>/dev/null) && \
        printf "[-] Apache user configuration:\n%s\n\n" "$apacheusr"

    if [ "$export" ] && [ "$apacheusr" ]; then
        mkdir --parents $format/etc-export/apache2/ 2>/dev/null
        cp /etc/apache2/envvars $format/etc-export/apache2/envvars 2>/dev/null
    fi

    #installed apache modules
    apachemodules=$(apache2ctl -M 2>/dev/null; httpd -M 2>/dev/null) && \
        printf "[-] Installed Apache modules:\n%s\n\n" "$apachemodules"

    #htpasswd check
    htpasswd="$(find / -name .htpasswd -print -exec cat {} \; 2>/dev/null)" && \
        printf "[-] htpasswd found - could contain passwords:\n%s\n\n" "$htpasswd"

    #anything in the default http home dirs
    apachehomedirs=$(ls -alhR /var/www/ 2>/dev/null; ls -alhR /srv/www/htdocs/ 2>/dev/null; ls -alhR /usr/local/www/apache2/data/ 2>/dev/null; ls -alhR /opt/lampp/htdocs/ 2>/dev/null) && \
        printf "[-] www home dir contents:\n%s\n\n" "$apachehomedirs"
}

interesting_files()
{
    printf "### INTERESTING FILES ####################################\n"

    #checks to see if various files are installed
    printf "[-] Useful file locations:\n" ; which nc 2>/dev/null ; which netcat 2>/dev/null ; which wget 2>/dev/null ; which nmap 2>/dev/null ; which gcc 2>/dev/null; which curl 2>/dev/null
    printf "\n"

    #limited search for installed compilers
    compiler=$(dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null) && \
        printf "[-] Installed compilers:\n%s\n\n" "$compiler"

    #manual check - lists out sensitive files, can we read/modify etc.
    printf "[-] Can we read/write sensitive files:\n" ; ls -la /etc/passwd 2>/dev/null ; ls -la /etc/group 2>/dev/null ; ls -la /etc/profile 2>/dev/null; ls -la /etc/shadow 2>/dev/null ; ls -la /etc/master.passwd 2>/dev/null
    printf "\n"

    #search for suid files - this can take some time so is only 'activated' with thorough scanning switch (as are all suid scans below)
    if [ "$thorough" = "1" ]; then
        findsuid=$(find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;) && \
            printf "[-] SUID files:\n%s\n\n" "$findsuid"
    fi

    if [ "$thorough" = "1" ]; then
        if [ "$export" ] && [ "$findsuid" ]; then
            mkdir $format/suid-files/ 2>/dev/null
            for i in $findsuid; do cp $i $format/suid-files/; done 2>/dev/null
        fi
    fi

    #list of 'interesting' suid files - feel free to make additions
    if [ "$thorough" = "1" ]; then
        intsuid=$(find / -perm -4000 -type f 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'vim'\|'emacs'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb\|pl' | xargs -r ls -la 2>/dev/null) && \
            printf "[+] Possibly interesting SUID files:\n%s\n\n" "$intsuid"
    fi

    #lists word-writable suid files
    if [ "$thorough" = "1" ]; then
        wwsuid=$(find / -perm -4007 -type f -exec ls -la {} 2>/dev/null \;) && \
            printf "[+] World-writable SUID files:\n%s\n\n" "$wwsuid"
    fi

    #lists world-writable suid files owned by root
    if [ "$thorough" = "1" ]; then
        wwsuidrt=$(find / -uid 0 -perm -4007 -type f -exec ls -la {} 2>/dev/null \;) && \
            printf "[+] World-writable SUID files owned by root:\n%s\n\n" "$wwsuidrt"
    fi

    #search for guid files - this can take some time so is only 'activated' with thorough scanning switch (as are all guid scans below)
    if [ "$thorough" = "1" ]; then
        findguid=$(find / -perm -2000 -type f -exec ls -la {} 2>/dev/null \;) && \
            printf "[-] GUID files:\n%s\n\n" "$findguid"
    fi

    if [ "$thorough" = "1" ]; then
        if [ "$export" ] && [ "$findguid" ]; then
            mkdir $format/guid-files/ 2>/dev/null
            for i in $findguid; do cp $i $format/guid-files/; done 2>/dev/null
        fi
    fi

    #list of 'interesting' guid files - feel free to make additions
    if [ "$thorough" = "1" ]; then
        intguid=$(find / -perm -2000 -type f 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'emacs'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb\|pl' | xargs -r ls -la 2>/dev/null) && \
            printf "[+] Possibly interesting GUID files:\n%s\n\n" "$intguid"
    fi

    #lists world-writable guid files
    if [ "$thorough" = "1" ]; then
        wwguid=$(find / -perm -2007 -type f -exec ls -la {} 2>/dev/null \;) && \
            printf "[+] World-writable GUID files:\n%s\n\n" "$wwguid"
    fi

    #lists world-writable guid files owned by root
    if [ "$thorough" = "1" ]; then
        wwguidrt=$(find / -uid 0 -perm -2007 -type f -exec ls -la {} 2>/dev/null \;) && \
            printf "[+] World-writable GUID files owned by root:\n%s\n\n" "$wwguidrt"
    fi

    #list all world-writable files excluding /proc and /sys
    if [ "$thorough" = "1" ]; then
        wwfiles=$(find / ! -path "*/proc/*" ! -path "/sys/*" -perm -2 -type f -exec ls -la {} 2>/dev/null \;) && \
            printf "[-] World-writable files (excluding /proc and /sys):\n%s\n\n" "$wwfiles"
    fi

    if [ "$thorough" = "1" ]; then
        if [ "$export" ] && [ "$wwfiles" ]; then
            mkdir $format/ww-files/ 2>/dev/null
            for i in $wwfiles; do cp --parents $i $format/ww-files/; done 2>/dev/null
        fi
    fi

    #are any .plan files accessible in /home (could contain useful information)
    usrplan=$(find /home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;) && \
        printf "[-] Plan file permissions and contents:\n%s\n\n" "$usrplan"

    if [ "$export" ] && [ "$usrplan" ]; then
        mkdir $format/plan_files/ 2>/dev/null
        for i in $usrplan; do cp --parents $i $format/plan_files/; done 2>/dev/null
    fi

    bsdusrplan=$(find /usr/home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;) && \
        printf "[-] Plan file permissions and contents:\n%s\n\n" "$bsdusrplan"

    if [ "$export" ] && [ "$bsdusrplan" ]; then
        mkdir $format/plan_files/ 2>/dev/null
        for i in $bsdusrplan; do cp --parents $i $format/plan_files/; done 2>/dev/null
    fi

    #are there any .rhosts files accessible - these may allow us to login as another user etc.
    rhostsusr=$(find /home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;) && \
        printf "[+] rhost config file(s) and file contents:\n%s\n\n" "$rhostsusr"

    if [ "$export" ] && [ "$rhostsusr" ]; then
        mkdir $format/rhosts/ 2>/dev/null
        for i in $rhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
    fi

    bsdrhostsusr=$(find /usr/home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;) && \
        printf "[+] rhost config file(s) and file contents:\n%s\n\n" "$bsdrhostsusr"

    if [ "$export" ] && [ "$bsdrhostsusr" ]; then
        mkdir $format/rhosts 2>/dev/null
        for i in $bsdrhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
    fi

    rhostssys=$(find /etc -iname hosts.equiv -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;) && \
        printf "[+] Hosts.equiv file and contents: \n%s\n\n" "$rhostssys"

    if [ "$export" ] && [ "$rhostssys" ]; then
        mkdir $format/rhosts/ 2>/dev/null
        for i in $rhostssys; do cp --parents $i $format/rhosts/; done 2>/dev/null
    fi

    #list nfs shares/permisisons etc.
    nfsexports=$(ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null) && \
        printf "[-] NFS config details: \n%s\n\n" "$nfsexports"

    if [ "$export" ] && [ "$nfsexports" ]; then
        mkdir $format/etc-export/ 2>/dev/null
        cp /etc/exports $format/etc-export/exports 2>/dev/null
    fi

    if [ "$thorough" = "1" ]; then
        #phackt
        #displaying /etc/fstab
        fstab=$(cat /etc/fstab 2>/dev/null) && \
            printf "[-] NFS displaying partitions and filesystems - you need to check if exotic filesystems \n%s\n\n" "$fstab"
    fi

    #looking for credentials in /etc/fstab
    fstab=$(grep username /etc/fstab 2>/dev/null |awk '{sub(/.*\username=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo username: 2>/dev/null; grep password /etc/fstab 2>/dev/null |awk '{sub(/.*\password=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo password: 2>/dev/null; grep domain /etc/fstab 2>/dev/null |awk '{sub(/.*\domain=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo domain: 2>/dev/null) && \
        printf "[+] Looks like there are credentials in /etc/fstab \n%s\n\n" "$fstab"

    if [ "$export" ] && [ "$fstab" ]; then
        mkdir $format/etc-exports/ 2>/dev/null
        cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
    fi

    fstabcred=$(grep cred /etc/fstab 2>/dev/null |awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1' 2>/dev/null | xargs -I{} sh -c 'ls -la {}; cat {}' 2>/dev/null) && \
        printf "[+] /etc/fstab contains a credentials file\n%s\n\n" "$fstabcred"

    if [ "$export" ] && [ "$fstabcred" ]; then
        mkdir $format/etc-exports/ 2>/dev/null
        cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
    fi

    #use supplied keyword and cat *.conf files for potential matches - output will show line number within relevant file path where a match has been located
    if [ "$keyword" = "" ]; then
        printf "[-] Can't search *.conf files as no keyword was entered\n"
    else
        confkey=$(find / -maxdepth 4 -name *.conf -type f -exec grep -Hn $keyword {} \; 2>/dev/null) && \
            printf "[-] Find keyword (%s) in .conf files (recursive 4 levels - output format filepath:identified line number where keyword appears):\n%s\n\n" "$keyword" "$confkey" || \
            printf "[-] Find keyword in .conf files (recursive 4 levels):\n'%s' not found in any .conf files\n" "$keyword"
    fi

    if [ "$keyword" = "" ]; then
        :
    else
        if [ "$export" ] && [ "$confkey" ]; then
            confkeyfile=$(find / -maxdepth 4 -name *.conf -type f -exec grep -lHn $keyword {} \; 2>/dev/null)
            mkdir --parents $format/keyword_file_matches/config_files/ 2>/dev/null
            for i in "$confkeyfile"; do cp --parents $i $format/keyword_file_matches/config_files/ ; done 2>/dev/null
        fi
    fi

    #use supplied keyword and cat *.php files for potential matches - output will show line number within relevant file path where a match has been located
    if [ "$keyword" = "" ]; then
        printf "[-] Can't search *.php files as no keyword was entered\n"
    else
        phpkey=$(find / -maxdepth 10 -name *.php -type f -exec grep -Hn $keyword {} \; 2>/dev/null) && \
            printf "[-] Find keyword (%s) in .php files (recursive 10 levels - output format filepath:identified line number where keyword appears):\n%s\n\n" "$keyword" "$phpkey" || \
            printf "[-] Find keyword in .php files (recursive 10 levels):'%s' not found in any .php files\n\n" "$keyword"
    fi

    if [ "$keyword" = "" ]; then
        :
    else
        if [ "$export" ] && [ "$phpkey" ]; then
            phpkeyfile=`find / -maxdepth 10 -name *.php -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
            mkdir --parents $format/keyword_file_matches/php_files/ 2>/dev/null
            for i in $phpkeyfile; do cp --parents $i $format/keyword_file_matches/php_files/ ; done 2>/dev/null
        fi
    fi

    #use supplied keyword and cat *.log files for potential matches - output will show line number within relevant file path where a match has been located
    if [ "$keyword" = "" ];then
        printf "[-] Can't search *.log files as no keyword was entered\n"
    else
        logkey=$(find / -maxdepth 4 -name *.log -type f -exec grep -Hn $keyword {} \; 2>/dev/null) $$ \
            printf "[-] Find keyword (%s) in .log files (recursive 4 levels - output format filepath:identified line number where keyword appears):\n%s\n\n" "$keyword" "$logkey" || \
            printf "[-] Find keyword in .log files (recursive 4 levels):'%s'not found in any .log files\n\n" "$keyword"
    fi

    if [ "$keyword" = "" ];then
        :
    else
        if [ "$export" ] && [ "$logkey" ]; then
            logkeyfile=`find / -maxdepth 4 -name *.log -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
            mkdir --parents $format/keyword_file_matches/log_files/ 2>/dev/null
            for i in $logkeyfile; do cp --parents $i $format/keyword_file_matches/log_files/ ; done 2>/dev/null
        fi
    fi

    #use supplied keyword and cat *.ini files for potential matches - output will show line number within relevant file path where a match has been located
    if [ "$keyword" = "" ];then
        printf "[-] Can't search *.ini files as no keyword was entered\n\n"
    else
        inikey=$(find / -maxdepth 4 -name *.ini -type f -exec grep -Hn $keyword {} \; 2>/dev/null) && \
            printf "[-] Find keyword (%s) in .ini files (recursive 4 levels - output format filepath:identified line number where keyword appears):\n%s\n\n" "$keyword" "$inikey" || \
            printf "[-] Find keyword in .ini files (recursive 4 levels):'%s' not found in any .ini files\n\n" "$keyword"
    fi

    if [ "$keyword" = "" ];then
        :
    else
        if [ "$export" ] && [ "$inikey" ]; then
            inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
            mkdir --parents $format/keyword_file_matches/ini_files/ 2>/dev/null
            for i in $inikey; do cp --parents $i $format/keyword_file_matches/ini_files/ ; done 2>/dev/null
        fi
    fi

    #quick extract of .conf files from /etc - only 1 level
    allconf=$(find /etc/ -maxdepth 1 -name *.conf -type f -exec ls -la {} \; 2>/dev/null) $$ \
        printf "[-] All *.conf files in /etc (recursive 1 level):\n%s\n\n" "$allconf"

    if [ "$export" ] && [ "$allconf" ]; then
        mkdir $format/conf-files/ 2>/dev/null
        for i in $allconf; do cp --parents $i $format/conf-files/; done 2>/dev/null
    fi

    #extract any user history files that are accessible
    usrhist=$(ls -la ~/.*_history 2>/dev/null) && \
        printf "[-] Current user's history files:\n%s\n\n" "$usrhist"

    if [ "$export" ] && [ "$usrhist" ]; then
        mkdir $format/history_files/ 2>/dev/null
        for i in $usrhist; do cp --parents $i $format/history_files/; done 2>/dev/null
    fi

    #can we read roots *_history files - could be passwords stored etc.
    roothist=$(ls -la /root/.*_history 2>/dev/null) && \
        printf "[+] Root's history files are accessible\n%s\n\n" "$roothist"

    if [ "$export" ] && [ "$roothist" ]; then
        mkdir $format/history_files/ 2>/dev/null
        cp $roothist $format/history_files/ 2>/dev/null
    fi

    #all accessible .bash_history files in /home
    checkbashhist=$(find /home -name .bash_history -print -exec cat {} 2>/dev/null \;) && \
        printf "[-] Location and contents (if accessible) of .bash_history file(s):\n%s\n\n" "$checkbashhist"

    #is there any mail accessible
    readmail=$(ls -la /var/mail 2>/dev/null) && \
        printf "[-] Any interesting mail in /var/mail:\n%s\n\n"

    #can we read roots mail
    readmailroot=$(head /var/mail/root 2>/dev/null) && \
        printf "[+] We can read /var/mail/root! (snippet below)\n%s\n\n" "readmailroot"

    if [ "$export" ] && [ "$readmailroot" ]; then
        mkdir $format/mail-from-root/ 2>/dev/null
        cp $readmailroot $format/mail-from-root/ 2>/dev/null
    fi
}

docker_checks()
{
    #specific checks - check to see if we're in a docker container
    dockercontainer=$(grep -i docker /proc/self/cgroup  2>/dev/null; find / -name "*dockerenv*" -exec ls -la {} \; 2>/dev/null) && \
        printf "[+] Looks like we're in a Docker container:\n%s\n\n" "$dockercontainer"

    #specific checks - check to see if we're a docker host
    dockerhost=$(docker --version 2>/dev/null; docker ps -a 2>/dev/null) && \
        printf "[+] Looks like we're hosting Docker:\n%s\n\n" "$dockerhost"

    #specific checks - are we a member of the docker group
    dockergrp=$(id | grep -i docker 2>/dev/null) && \
        printf "[+] We're a member of the (docker) group - could possibly misuse these rights\n%s\n\n" "$dockergrp"

    #specific checks - are there any docker files present
    dockerfiles=$(find / -name Dockerfile -exec ls -l {} 2>/dev/null \;) && \
        printf "[-] Anything juicy in the Dockerfile:\n%s\n\n" "$dockerfiles"

    #specific checks - are there any docker files present
    dockeryml=$(find / -name docker-compose.yml -exec ls -l {} 2>/dev/null \;) && \
        printf "[-] Anything juicy in docker-compose.yml:\n%s\n\n" "$dockeryml"
}

lxc_container_checks()
{
    #specific checks - are we in an lxd/lxc container
    lxccontainer=$(grep -qa container=lxc /proc/1/environ 2>/dev/null) && \
        printf "[+] Looks like we're in a lxc container:\n%s\n\n" "$lxccontainer"

    #specific checks - are we a member of the lxd group
    lxdgroup=`id | grep -i lxd 2>/dev/null`
    if [ "$lxdgroup" ]; then
        printf "[+] We're a member of the (lxd) group - could possibly misuse these rights\n\n"
    fi
}

footer()
{
    printf "### SCAN COMPLETE ####################################\n"
}

call_each()
{
    header
    debug_info
    system_info
    user_info
    environmental_info
    job_info
    networking_info
    services_info
    software_configs
    interesting_files
    docker_checks
    lxc_container_checks
    footer
}

while getopts "h:k:r:e:t" option; do
    case "${option}" in
        k) keyword=${OPTARG};;
        r) report=${OPTARG}"-"`date +"%d-%m-%y"`;;
        e) export=${OPTARG};;
        t) thorough=1;;
        h) usage; exit;;
        *) usage; exit;;
    esac
done

call_each | tee -a $report 2> /dev/null
#EndOfScript
