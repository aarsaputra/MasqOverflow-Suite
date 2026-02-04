#!/bin/bash
echo "[*] Initializing MasqOverflow-Suite Environment..."

# Update and install python3-pip if missing
if ! command -v pip3 &> /dev/null; then
    echo "[!] pip3 not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y python3-pip
fi

# Install dependencies
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt

echo "[+] Installation Complete!"
echo "    Run: sudo python3 masq_overflow.py <TARGET_IP>"
