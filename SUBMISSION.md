# VulDB Submission Sheet — DIR-878-cves

> Each vulnerability is submitted **separately** (one form per entry). Description is plain text
> (VulDB disables markup) — copy the fenced block verbatim, without the fence.

## Shared fields

| Field | Value |
|---|---|
| Vendor | `D-Link` (select the existing entry) |
| Product | `DIR-878` |
| Version or Commit | `1.20B05` |

---

## Entry 1 — GetCAPTCHAsetting Cookie uid heap overflow (pre-auth)

| Field | Value |
|---|---|
| Vulnerability | `Heap-based Buffer Overflow (CWE-122)` |
| Advisory / Exploit URL | https://github.com/Zhaoyang-haha/DIR-878-cves/tree/main/01-captcha-uid-heap-overflow |
| Request a CVE | ☑ checked |
| Vendor contacted beforehand | ☑ checked (only after the vendor e-mail is actually sent) |

**Description (paste as plain text):**

```
A heap-based buffer overflow vulnerability was discovered in D-Link DIR-878 (REV A) firmware v1.20B05. The GetCAPTCHAsetting HNAP handler in bin/prog.cgi copies the attacker-controlled uid value from the HTTP Cookie header into an 11-byte heap allocation (malloc(0xb)) using strcpy, without any length check. The endpoint serves the login page and is reachable without authentication. Reproduction: curl -X POST /HNAP1/ with SOAPAction GetCAPTCHAsetting and Cookie uid=<512 bytes> returns HTTP 500 and crashes the FastCGI worker (SIGSEGV), while a short uid returns 200 OK; the crash threshold at ~11 bytes matches the malloc(0xb) size. An unauthenticated adjacent-network attacker can repeatedly crash the web management interface. The overflowed bytes are fully attacker-controlled, so heap metadata corruption and further code execution are plausible but were not developed. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (6.5). Discovered by Zimo-666 via static reverse engineering and dynamic differential testing.
```

---

## Entry 2 — SetWanSettings ConfigDNS stack overflow (wan0, Static/DHCP)

| Field | Value |
|---|---|
| Vulnerability | `Stack-based Buffer Overflow (CWE-121)` |
| Advisory / Exploit URL | https://github.com/Zhaoyang-haha/DIR-878-cves/tree/main/02-setwansettings-dns-stack-overflow |
| Request a CVE | ☑ checked |
| Vendor contacted beforehand | ☑ checked (only after the vendor e-mail is actually sent) |

**Description (paste as plain text):**

```
A stack-based buffer overflow vulnerability was discovered in D-Link DIR-878 (REV A) firmware v1.20B05. In the SetWanSettings HNAP handler (default WANID = wan0), the Static branch helper (0x462aa0) and the DHCP branch helper (0x46342c) concatenate the user-controlled ConfigDNS/Primary and ConfigDNS/Secondary fields into a 64-byte stack buffer via sprintf plus strcat, before any IP-format validation. A Primary of about 164 bytes overwrites the saved return address. The handler is reachable pre-authentication via the previously disclosed HNAP authentication bypass (CVE-2020-15633 class), verified on v1.20B05. Reproduction: POST /HNAP1/?GetCAPTCHAsetting with SOAPAction SetWanSettings, Type=Static and Primary=200 x "A" returns HTTP 500 with SIGSEGV and a core dump; gdb forensics show the crash inside uClibc strcat with registers saturated by attacker bytes (a1, t1-t7 = 0x41414141). A short value returns OK. This wan0 instance is distinct from CVE-2026-90693 (wan3) and from the CVE-2022-4656x family (Password fields of SetWanSettings2/3). An unauthenticated adjacent-network attacker can crash the web management handler; return-address overwrite gives code-execution potential that was not further developed. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (6.5). Discovered by Zimo-666 via static reverse engineering, dynamic differential testing and gdb register forensics.
```

---

## Entry 3 — SetVLANSettings → SetTriggerADIC second-order stack overflow

| Field | Value |
|---|---|
| Vulnerability | `Stack-based Buffer Overflow (CWE-121)` |
| Advisory / Exploit URL | https://github.com/Zhaoyang-haha/DIR-878-cves/tree/main/03-settriggeradic-vlan-stack-overflow |
| Request a CVE | ☑ checked |
| Vendor contacted beforehand | ☑ checked (only after the vendor e-mail is actually sent) |

**Description (paste as plain text):**

```
A stack-based buffer overflow vulnerability was discovered in D-Link DIR-878 (REV A) firmware v1.20B05. The SetVLANSettings HNAP handler stores the user-controlled VLANID:0/VID field without any length check into the nvram key wan_wan0_ifname (up to 255 bytes). The SetTriggerADIC handler (0x459b60) then concatenates that stored value with sprintf into a 128-byte stack buffer to build pppoe-discovery and udhcpc-discovery command lines. A purely alphanumeric VID of 98+ characters overflows the stack frame; no shell metacharacters are needed, so metacharacter filtering cannot fix this defect. The command-injection facet of the same field is covered by CVE-2024-48636 and is not claimed here. The handlers are reachable pre-authentication via the previously disclosed HNAP bypass (CVE-2020-15633 class), verified on v1.20B05. Reproduction: SetVLANSettings with VID="1"+150x"D" returns OK and stores the value; a subsequent SetTriggerADIC with TriggerADIC=true returns HTTP 500, the prog.cgi FastCGI worker dies (core dump attributed to prog.cgi), and the downstream udhcpc-discovery process also crashes. An unauthenticated adjacent-network attacker can repeatedly crash the web management handler and disrupt WAN services; the overwrite reaches the saved return-address area, giving code-execution potential that was not further developed. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (6.5). Discovered by Zimo-666 via static reverse engineering and dynamic end-to-end reproduction with core attribution.
```

---

## Entry 4 — GetCAPTCHAsetting missing Cookie NULL pointer dereference (pre-auth)

| Field | Value |
|---|---|
| Vulnerability | `NULL Pointer Dereference (CWE-476)` |
| Advisory / Exploit URL | https://github.com/Zhaoyang-haha/DIR-878-cves/tree/main/04-captcha-no-cookie-null-deref |
| Request a CVE | ☑ checked |
| Vendor contacted beforehand | ☑ checked (only after the vendor e-mail is actually sent) |

**Description (paste as plain text):**

```
A NULL pointer dereference vulnerability was discovered in D-Link DIR-878 (REV A) firmware v1.20B05. The GetCAPTCHAsetting HNAP handler in bin/prog.cgi (0x436158) executes strcpy(malloc(0xb), uid) when registering a new uid; when the request carries no Cookie header at all, the cookie parser (0x424610) leaves uid NULL and strcpy reads from address 0, causing an immediate SIGSEGV. The endpoint serves the login page and requires no authentication. Reproduction: curl -X POST /HNAP1/ with SOAPAction GetCAPTCHAsetting and an empty SOAP body returns HTTP 500 and kills the FastCGI worker (core dump attributed to prog.cgi), while the identical request with any Cookie header returns 200 OK. An unauthenticated adjacent-network attacker can repeatedly crash the web management interface with a single trivial request (denial of service). Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (6.5). Discovered by Zimo-666 via dynamic differential testing (Cookie present vs. absent) with core attribution and static root-cause analysis.
```

---

## Entry 5 — SetWanSettings ConfigDNS overflow (L2TP/PPTP branches)

| Field | Value |
|---|---|
| Vulnerability | `Stack-based Buffer Overflow (CWE-121)` |
| Advisory / Exploit URL | https://github.com/Zhaoyang-haha/DIR-878-cves/tree/main/05-setwansettings-l2tp-pptp-dns-overflow |
| Request a CVE | ☑ checked |
| Vendor contacted beforehand | ☑ checked (only after the vendor e-mail is actually sent) |

**Description (paste as plain text):**

```
A stack-based buffer overflow vulnerability was discovered in D-Link DIR-878 (REV A) firmware v1.20B05. In the SetWanSettings HNAP handler (default WANID = wan0), the L2TP and PPTP branch helper (0x464134) copies the user-controlled ConfigDNS/Primary and ConfigDNS/Secondary fields into a 72-byte stack buffer via strncat(buf, src, strlen(src)), equivalent to an unbounded strcat, with no validation at any point. Disassembly confirms the saved return address at buffer offset 72; a Primary of 100 bytes crashes the process in both the L2TP and PPTP branches. The handler is reachable pre-authentication via the previously disclosed HNAP bypass (CVE-2020-15633 class), verified on v1.20B05. Reproduction: POST /HNAP1/?GetCAPTCHAsetting with SOAPAction SetWanSettings, Type=L2TP and Primary=100 x "A" returns HTTP 500 with FastCGI worker death and a core dump; two independent gdb captures show attacker bytes entering pointer-level dereferences (strlen called on 0x41414141 and on bytes of the Secondary value). A short Primary returns OK. This instance is distinct from the Static/DHCP branch helpers, from CVE-2026-90693 (wan3), and from the CVE-2022-4656x family (Password fields). An unauthenticated adjacent-network attacker can crash the web management handler; the return-address overwrite gives code-execution potential that was not further developed. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (6.5). Discovered by Zimo-666 via static reverse engineering, disassembly frame analysis and two gdb register captures.
```

---

## Entry 6 — GetListDirectory path traversal (directory enumeration)

| Field | Value |
|---|---|
| Vulnerability | `Path Traversal (CWE-22)` |
| Advisory / Exploit URL | https://github.com/Zhaoyang-haha/DIR-878-cves/tree/main/06-getlistdirectory-path-traversal |
| Request a CVE | ☑ checked |
| Vendor contacted beforehand | ☑ checked (only after the vendor e-mail is actually sent) |

**Description (paste as plain text):**

```
A path traversal vulnerability was discovered in D-Link DIR-878 (REV A) firmware v1.20B05. The GetListDirectory HNAP handler in bin/prog.cgi (0x4934fc) concatenates the user-controlled ListDirectoryPath field with snprintf("/mnt%s") and passes it directly to opendir(); the supposed validation function (0x493134) contains no ".." or absolute-path check and is merely an opendir/readdir entry counter. The endpoint is reachable without any credentials. Reproduction: curl -X POST /HNAP1/?GetCAPTCHAsetting with SOAPAction GetListDirectory and ListDirectoryPath=/../usr returns HTTP 200 listing the first-level subdirectory names of /usr (local, lib, codepages, sbin, bin); /../var likewise lists tmp, run, web, private; the baseline path / returns an empty list. An unauthenticated adjacent-network attacker can enumerate first-level directory names under arbitrary paths outside /mnt, gaining filesystem-structure reconnaissance for staging further attacks. File contents cannot be read and regular files are not listed (directory entries only). Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (3.5). Discovered by Zimo-666 via static reverse engineering and dynamic differential testing.
```

---

> **Note on version scope.** v1.20B05 is the verified build. The DIR-878 is EoL (SAP10475) and later
> v1.30B08 hotfix builds share the HNAP codebase lineage but were not individually re-verified — the
> advisories state this explicitly. VulDB has accepted other DIR-878 entries on 1.20B05.
