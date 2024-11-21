#!/bin/bash

# Jasoos the Automated Enumeration Tool
# Author: Kathan Parekh
# Purpose: Information gathering using Nmap, WhatWeb, GoBuster, DNSenum, and Nikto

# Check if the user provided a target
if [ -z "$1" ]; then
    echo "Usage: $0 <target>"
    echo "Example: $0 example.com"
    exit 1
fi

TARGET=$1
OUTPUT_DIR="recon_results"
mkdir -p $OUTPUT_DIR

echo -e "\n[+] Starting automated reconnaissance for target: $TARGET"
echo -e "[+] Results will be saved in the directory: $OUTPUT_DIR\n"

# Step 1: Run Nmap for port scanning and service enumeration
echo -e "[+] Running Nmap..."
nmap -sC -sV -oN "$OUTPUT_DIR/nmap_scan.txt" $TARGET
echo -e "[+] Nmap scan completed. Results saved in $OUTPUT_DIR/nmap_scan.txt\n"

# Step 2: Run WhatWeb for web application fingerprinting
echo -e "[+] Running WhatWeb..."
whatweb $TARGET > "$OUTPUT_DIR/whatweb_results.txt"
echo -e "[+] WhatWeb scan completed. Results saved in $OUTPUT_DIR/whatweb_results.txt\n"

# Step 3: Run GoBuster for directory brute-forcing
echo -e "[+] Running GoBuster for directory enumeration..."
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -o "$OUTPUT_DIR/gobuster_results.txt"
echo -e "[+] GoBuster scan completed. Results saved in $OUTPUT_DIR/gobuster_results.txt\n"

# Step 4: Run DNSenum for DNS information
echo -e "[+] Running DNSenum..."
dnsenum $TARGET > "$OUTPUT_DIR/dnsenum_results.txt"
echo -e "[+] DNSenum scan completed. Results saved in $OUTPUT_DIR/dnsenum_results.txt\n"

# Step 5: Run Nikto for web server vulnerability scanning
echo -e "[+] Running Nikto..."
nikto -h $TARGET -output "$OUTPUT_DIR/nikto_results.txt"
echo -e "[+] Nikto scan completed. Results saved in $OUTPUT_DIR/nikto_results.txt\n"

echo -e "[+] Reconnaissance completed. Check the $OUTPUT_DIR directory for results.\n"
