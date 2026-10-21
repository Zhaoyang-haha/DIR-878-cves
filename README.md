# D-Link DIR-878 (REV A) Firmware v1.20B05 — Security Vulnerability Disclosures

This repository documents **five independently discovered security vulnerabilities** in the
D-Link DIR-878 (hardware revision A) router firmware **v1.20B05**, found during an authorized
security assessment. All issues were verified against the original firmware binary (`bin/prog.cgi`,
the HNAP/FastCGI handler) running in a faithful rehosting environment (qemu-user MIPS32LE +
firmware-shipped lighttpd + an NVRAM shim), with dynamic differential testing and, for the
memory-corruption issues, gdb register-level forensics.

> **Status:** CVE identifiers requested via VulDB — entries are titled `CVE: Not assigned` until assignment.
> Vendor notification: pending (see each advisory's Discovery section).

## Affected Product

- **Vendor:** D-Link
- **Product:** DIR-878, Hardware Revision A (Ax)
- **Firmware:** v1.20B05 (verified; SHA256 of the vendor image `22724f7e…dccf7e`)
- **Lifecycle:** The DIR-878 reached End-of-Sale / End-of-Life (EoL announcement SAP10475);
  firmware line: v1.20B05 (2019-07) → v1.30B08 + hotfix (2021). Later v1.30B08 hotfix builds share
  the same HNAP codebase lineage but were not individually re-verified for every issue.

## Vulnerability Index

| # | Directory | Component / Action | Type | Pre-auth | CVSS 3.1 |
|---|-----------|--------------------|------|----------|----------|
| 1 | [01-captcha-uid-heap-overflow](01-captcha-uid-heap-overflow/) | `GetCAPTCHAsetting` | CWE-122 Heap-based Buffer Overflow (Cookie `uid` → `strcpy` into `malloc(0xb)`) | ✅ | 6.5 |
| 2 | [02-setwansettings-dns-stack-overflow](02-setwansettings-dns-stack-overflow/) | `SetWanSettings` (wan0, Static & DHCP) | CWE-121 Stack-based Buffer Overflow (`ConfigDNS/Primary|Secondary` → `sprintf`+`strcat` into 64-byte stack buffer) | ✅ (via known HNAP bypass) | 6.5 |
| 3 | [03-settriggeradic-vlan-stack-overflow](03-settriggeradic-vlan-stack-overflow/) | `SetVLANSettings` → `SetTriggerADIC` | CWE-121 Stack-based Buffer Overflow (over-long `VID` stored in nvram, second-order `sprintf` into 128-byte stack buffer) | ✅ (via known HNAP bypass) | 6.5 |
| 4 | [05-setwansettings-l2tp-pptp-dns-overflow](05-setwansettings-l2tp-pptp-dns-overflow/) | `SetWanSettings` (wan0, L2TP & PPTP) | CWE-121 Stack-based Buffer Overflow (`ConfigDNS` → `strncat(buf,src,strlen(src))` into 72-byte stack buffer, no validation at all) | ✅ (via known HNAP bypass) | 6.5 |
| 5 | [06-getlistdirectory-path-traversal](06-getlistdirectory-path-traversal/) | `GetListDirectory` | CWE-22 Path Traversal → CWE-200 Information Disclosure (arbitrary first-level directory-name enumeration outside `/mnt`) | ✅ | 3.5 |

### Scoring rationale

CVSS scores follow a conservative, evidence-first policy: every memory-corruption issue was
dynamically reproduced as a pre-authentication crash (HTTP 500 / SIGSEGV of the FastCGI worker),
which is scored as `AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **6.5**. Where register forensics show
attacker bytes reaching the saved return address or dereferenced pointers (issues 2, 3, 5), the
advisory text documents the code-execution potential explicitly, but the score reflects only the
proven impact. Issue 5 is scored 3.5 because only directory *names* (one level deep) are disclosed.

## Notes on scope and novelty

- The **command-injection facet** of the `SetVLANSettings` `VID` field is **not claimed** here:
  it is already covered by CVE-2024-48636. Issue 03 claims only the distinct stack-overflow facet
  (triggered by a purely alphanumeric over-long `VID`, which no metacharacter filter can fix).
- Issues 2 and 4 concern the **wan0** instance of the WAN-settings DNS-concatenation pattern
  (default `WANID`), distinct from CVE-2026-90693 (wan3) and from the CVE-2022-4656x family
  (`Password` fields of `SetWanSettings2/3`, different parameters and sinks).
- The HNAP authentication bypass used to reach `Set*` handlers pre-authentication is the
  previously disclosed CVE-2020-15633 class behavior (`POST /HNAP1/?GetCAPTCHAsetting` carrying
  an arbitrary `SOAPAction`), verified present in v1.20B05. Issues 1 and 5 need no bypass at all.

## Research environment

All tests were performed in an isolated rehosting environment; no production devices or
third-party networks were affected. Firmware was decrypted from the vendor's public download
(SHRS envelope), unpacked, and the original `prog.cgi` (908,828 bytes, hash-matched to the
unpacked firmware) was executed under qemu-user with the firmware's own lighttpd front-end.

## Credits

Discovered by **Zimo-666** (independent security researcher), 2026-10-12, via static reverse
engineering (full HNAP dispatch-table mapping: 147 actions) plus dynamic differential testing.

---

## Repository files

| Path | Content |
|---|---|
| `01-captcha-uid-heap-overflow/` | Advisory + `poc.sh` — Cookie `uid` heap overflow (pre-auth) |
| `02-setwansettings-dns-stack-overflow/` | Advisory + `poc.sh` — `ConfigDNS` stack overflow, Static/DHCP |
| `03-settriggeradic-vlan-stack-overflow/` | Advisory + `poc.sh` — `VID` second-order stack overflow |
| `04-captcha-no-cookie-null-deref/` | Advisory + `poc.sh` — missing Cookie NULL dereference (pre-auth) |
| `05-setwansettings-l2tp-pptp-dns-overflow/` | Advisory + `poc.sh` — `ConfigDNS` overflow, L2TP/PPTP |
| `06-getlistdirectory-path-traversal/` | Advisory + `poc.sh` — path traversal / directory enumeration |

Scripts are reproductions of the requests recorded in each advisory; the quoted observed outputs
in the advisories are the test evidence.

All PoCs are non-destructive: crash cases only kill the FastCGI worker, which lighttpd restarts,
and nothing is written to flash. Issue 03 writes an nvram key as part of the trigger — its
cleanup step is stated in the advisory.
