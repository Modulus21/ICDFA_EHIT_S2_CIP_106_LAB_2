# Dynamic Malware Analysis of a UPX-Packed Windows Executable

**Controlled static and dynamic analysis of a packed 32-bit Windows sample (`financials-xls.exe`) in an isolated FLARE-VM lab, with evidence-based findings, IOCs and MITRE ATT&CK mapping.**

| | |
|---|---|
| **Author** | Habeeb Sikiru |
| **Focus** | Malware analysis, dynamic analysis, evidence handling, network correlation, technical reporting |
| **Environment** | VirtualBox, FLARE-VM (Windows 11), Host-only network with FakeNet-NG simulated services |
| **Analysis date** | 1 October 2026 (VM clock) |
| **Overall confidence** | High (packing, alert, network requests); Medium (persistence, likely capability); Low (any downloaded payload) |

> **Safety note:** All analysis was performed inside an isolated virtual machine with no Internet access. The malware sample is **not** included in this repository. All network indicators below are **defanged** (`[.]`) so they cannot be clicked or resolved by accident.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Executive Summary](#executive-summary)
3. [Objectives](#objectives)
4. [Skills Demonstrated](#skills-demonstrated)
5. [Technologies and Tools Used](#technologies-and-tools-used)
6. [Lab Environment](#lab-environment)
7. [Methodology](#methodology)
8. [Evidence and Analysis](#evidence-and-analysis)
9. [Findings](#findings)
10. [Challenges Encountered](#challenges-encountered)
11. [Recommendations](#recommendations)
12. [Key Learning Outcomes](#key-learning-outcomes)
13. [Professional Value](#professional-value)
14. [Conclusion](#conclusion)
15. [Repository Structure](#repository-structure)
17. [Disclaimer](#disclaimer)
18. [References, Attribution and Acknowledgements](#references-attribution-and-acknowledgements)

---

## Project Overview

This project documents a complete malware-analysis workflow against a course-provided Windows executable named `financials-xls.exe`. The sample was treated as untrusted code from the first step: the environment was isolated and baselined before anything was run, the file was hashed and verified at every stage, packing was proven with independent evidence before the file was unpacked, and the sample was executed only under active monitoring.

The goal was not only to find out what the sample does, but to **separate what was observed from what was inferred**, to state confidence levels, and to be explicit about what the evidence could not show.

**Scenario in one paragraph:** a file named like a spreadsheet and carrying an Excel icon turned out to be a UPX-packed GUI program that shows a fake spyware-infection alert, contacts a hard-coded IP address over HTTP, and adds Run-key persistence entries.

---

## Executive Summary

`financials-xls.exe` is a 43,520-byte, 32-bit Windows GUI executable packed with UPX. Four independent checks (signature detection, section and entropy structure, UPX's own integrity test and a successful unpack) support the packing conclusion with **high confidence**. Unpacking produced a 57,344-byte file with a conventional section layout, lower entropy and an import table of 85 functions instead of 10.

The sample was executed three times in one monitoring window (20:49 to 20:57 VM time) on a Host-only network with simulated Internet services. In the one run captured end to end (PID 2868), it started at 20:57:10, displayed a fake "Your computer is infected!" alert and exited by itself at 20:57:12. On every run it sent one HTTP GET to a hard-coded address (`69.50.175[.]181:80`, `/download.php`, Host `download[.]bravesentry[.]com`). Two new `HKCU\...\Run` values appeared during the window: one pointing at the sample itself and one pointing at `C:\Windows\xpupdate.exe`.

**Likely capability:** a scareware or rogue-security-style program that contacts a remote server and sets up Run-key persistence. Confidence is **medium** overall and **low** for anything a downloaded payload might do, because the server was simulated.

**Key results**

| Area | Result | Confidence |
|---|---|---|
| Packing | UPX packed; unpacked from 43,520 to 57,344 bytes | High |
| Process behaviour | Run 3: PID 2868, lifetime about 2 s, fake spyware alert, self-exit | High (run 3); Medium (runs 1 and 2) |
| Network | Three HTTP GETs to `69.50.175[.]181:80`, intercepted by FakeNet-NG | High that requests occurred; Low on purpose |
| Persistence | Two new HKCU Run values | Medium-High (`con`); Medium (`Windows update loader`) |
| Not established | File activity, full process tree, anti-analysis behaviour, existence of `xpupdate.exe` | Stated as limitations |

---

## Objectives

1. Build a safe dynamic-analysis environment and prove its isolation controls before handling the sample.
2. Record an evidence baseline (processes, connections, startup locations, scheduled tasks, hash of the original file).
3. Confirm UPX packing with independent tools, unpack the sample without executing it, and keep the original and unpacked files traceable by hash.
4. Observe the sample under monitoring and record process, file, registry and persistence activity that is directly visible in the evidence.
5. Capture attempted network communication safely and correlate it with the responsible process and timestamp.
6. Map supported observations to MITRE ATT&CK with confidence levels, extract indicators of compromise, and state limitations clearly.

---

## Skills Demonstrated

Only skills supported by the work in this project are listed.

| Skill area | How it was demonstrated |
|---|---|
| **Malware analysis (static)** | Identified UPX packing using signature detection, section layout, per-section entropy, import analysis and the packer's own integrity test; unpacked the file safely and compared both versions |
| **Malware analysis (dynamic)** | Executed the sample under monitoring and recorded its process, visible behaviour, registry persistence and network activity |
| **Network analysis** | Interpreted FakeNet-NG connection logs, identified destination, port, protocol, HTTP request structure and URI pattern, and correlated each connection to a process ID |
| **Log analysis** | Read and filtered FakeNet-NG log output to separate sample traffic from operating-system background traffic |
| **Digital forensics practice** | SHA-256 hashing before, during and after analysis; snapshot-based restore points; separate folders for original, unpacked and evidence files; chronological evidence log |
| **Indicator extraction and threat mapping** | Produced an IOC table with sources and timestamps and mapped observations to MITRE ATT&CK with confidence levels |
| **Lab safety and isolation** | Verified Host-only networking, disabled clipboard, drag-and-drop and shared folders, and used simulated services so no traffic left the lab |
| **Documentation and reporting** | Kept a timestamped evidence log, separated observed facts from inference, and recorded errors, deviations and limitations openly |

**Not part of this project:** SIEM investigation, vulnerability assessment, threat hunting across an environment, and live incident response were not performed and are not claimed.

---

## Technologies and Tools Used

| Tool | Version / detail | Purpose |
|---|---|---|
| Oracle VirtualBox / VBoxManage | Host | VM isolation proof and snapshots |
| FLARE-VM on Windows 11 | Build 10.0.22621.1555 | Analysis workstation |
| Windows PowerShell | Guest | Baselines, hashing, execution, comparisons |
| UPX | 5.2.0 | Packing test (`-t`, `-l`) and unpacking (`-d -o`) |
| Detect It Easy (DIE) | v3.10 | Packer signature, entropy, sections |
| pestudio | 9.61 | Sections, entropy, imports, indicators |
| PE Detective | Deep scan | Independent packer-signature check |
| Process Monitor, Process Explorer | Sysinternals | Process and file monitoring during execution |
| Regshot | 1.9.1 x64 Unicode | Registry before/after comparison |
| Autoruns | Sysinternals | Autostart baseline and comparison |
| FakeNet-NG | 3.5 | Simulated network services and per-process connection logging |
| Wireshark | Capture file saved | Packet capture |

PE-bear was not installed in this build. PE Carve was present but deliberately not used, because it extracts embedded content and could alter the evidence set.

---

## Lab Environment

**Isolation controls (verified from the host with `VBoxManage showvminfo` and the VirtualBox interface)**

| Control | State |
|---|---|
| Network | Host-only only (NIC 2); NIC 1 and NICs 3 to 8 disabled |
| Internet access | None; services simulated inside the guest by FakeNet-NG |
| Shared clipboard (including file transfers) | Disabled |
| Drag and drop | Disabled |
| Shared folders | None |
| USB | xHCI controller enabled, but no filters and no attached devices |

**Environment record**

| Item | Value |
|---|---|
| VM name / guest hostname | `windows11` / `flare` |
| Guest OS | Windows 11 64-bit, `10.0.22621.1555` |
| Resources | 8192 MB RAM, 2 CPUs, 97.01 GB disk |
| Working folders | `C:\L\o` (original), `C:\L\u` (unpacked), `C:\L\e` (evidence) |

**Snapshot chain (host clock)**

| Snapshot | Taken | Role |
|---|---|---|
| `win11` | 9/29/2026 7:59 PM | Base FLARE-VM state |
| `Snapshot 2` | 9/30/2026 12:02 AM | Intermediate preparation state |
| `Lab02_PreExecution_Baseline` | 10/1/2026 3:08 PM | Clean baseline; restore target |
| `Lab02_PreExecution_ToolsReady` | 10/1/2026 9:04 PM | Tools-ready state (see timing caveat under [Challenges](#challenges-encountered)) |
| `Lab02_PostExecution_Evidence` | 10/1/2026 10:06 PM | Post-run evidence preserved |

---

## Methodology

The work followed five phases. Each phase produced evidence that the next phase depended on.

| Phase | What was done | Why it matters |
|---|---|---|
| **1. Environment preparation** | Verified isolation, took a clean snapshot, recorded environment details and baselines, hashed the original sample | Makes later claims defensible: "this value was not there before" and "this file is the one I started with" |
| **2. Packing validation and unpacking** | Checked UPX indicators with several tools, unpacked to a new filename, hashed both files, compared them | Shows how a conclusion was reached instead of assuming it |
| **3. Controlled runtime observation** | Started monitoring, executed the sample, recorded process, registry and startup changes | Turns static suspicion into observed behaviour |
| **4. Network and behaviour correlation** | Logged connection attempts with FakeNet-NG and matched them to process IDs and timestamps | Links network activity to the responsible process |
| **5. Findings and restoration** | Built the findings matrix, IOCs and ATT&CK mapping, re-verified file integrity, restored the clean snapshot | Closes the loop and leaves the lab in a known-good state |

---

## Evidence and Analysis

> Timestamps in PowerShell evidence are the FLARE prompt times (when each prompt was drawn), so a command was entered at or shortly after that time. "Host" times come from the VirtualBox interface.

### Phase 1: Environment preparation

| Action | Purpose | Result | Significance |
|---|---|---|---|
| Ran `VBoxManage showvminfo "windows11"` filtered for clipboard, drag-and-drop, NIC, shared folder and USB lines (first attempt returned a `FindMachine` error and was re-run with the correct VM name) | Prove isolation from configuration data rather than from memory | NIC 1 and 3 to 8 disabled; NIC 2 Host-only; clipboard, file transfers and drag-and-drop disabled; no shared folders; xHCI enabled with no devices | Configuration-level proof that nothing could cross the VM boundary except Host-only traffic |
| Reviewed VirtualBox Manager details and Settings | Provide a second, visual confirmation | Windows 11 64-bit, 8192 MB, 2 CPUs; Adapter 2 Host-only; clipboard and drag-and-drop Disabled | Confirms the same controls through the GUI |
| Took snapshot `Lab02_PreExecution_Baseline` (host 3:08 PM) | Create a clean restore point | Snapshot created, taken before the working folders (4:52 PM) and the extracted sample (5:15 PM) existed | Allows rollback after execution. The time the archive reached the VM was not recorded, so no claim is made about it |
| Created `C:\L\o` and `C:\L\e`; ran `hostname; cmd /c ver; date` | Separate evidence by type and record the environment and time reference | Host `flare`; Windows `10.0.22621.1555`; 4:55:54 PM on 1 October 2026 | Establishes the environment record and the VM time reference |
| Captured baselines: `netstat -ano`, `reg query` on HKCU and HKLM Run keys, `schtasks` (saved as `b_net`, `b_u`, `b_m`, `b_t`, 17:05 to 17:11) | Record the "before" state | Four baseline files saved. The process list was shown on screen but `b_ps.txt` was not saved | Enables before/after comparison; the missing process baseline is recorded as a limitation |
| Confirmed the sample sat in `C:\L\o` (43,520 bytes, file-system date 2/7/2018 12:55 AM) without executing it | Verify extraction without execution | File present, size matches later tool output | Start of chain of custody |
| Ran `Get-FileHash` on the original (17:16:37; first attempt mistyped and re-run) | Fix the file's identity before any further action | SHA-256 `F09FFE74770A7229DDEF667BC95FA73E0886ADF8739CDFFF36101443975E5B5A` | A fixed fingerprint that later hashes are compared against |

### Phase 2: Packing validation and approved unpacking

| Action | Purpose | Result | Significance |
|---|---|---|---|
| Checked tools with `upx -V` and `where.exe`; located DIE with `gci` | Confirm approved tools exist | UPX 5.2.0; `diec` not on PATH; DIE found in `C:\Tools\die` and called by full path | Documented tool gap, resolved without changing the method |
| Scanned the original with DIE (command line and GUI) | Identify the packer by signature | `Packer: UPX(3.92)[NRV,best]`; GUI also raised a heuristic "compressed or packed data" detection | First independent indicator |
| Reviewed DIE entropy and sections | Measure compression statistically | Whole-file entropy 5.565 (DIE summary reads "not packed 69%"); per-region: PE header 6.985, `UPX1` 7.844, both marked "packed" | Shows why per-section entropy is the correct measure: the low-entropy `.rsrc` dilutes the whole-file average |
| Inspected the original in pestudio | Cross-check structure and imports | Sections `UPX0` (raw size 0, virtual size 57,344), `UPX1` (14,848 bytes, entropy 7.844), `.rsrc` (27,648 bytes, entropy 3.470); entry point `0x00012790` inside `UPX1`; `UPX0`/`UPX1` flagged self-modifying; 10 imports | Matches the classic UPX layout: empty section to decompress into, compressed section holding the stub, few visible imports |
| Ran PE Detective deep scan | Third method: signature families | Three UPX signature families matched; best match "UPX 2.90 [LZMA] (Delphi stub)" | Agreement on UPX; disagreement on version is noted |
| Ran `upx -t` and `upx -l` | Let the packer verify itself without writing or executing | `[OK]`; 57,344 unpacked vs 43,520 packed (75.89%) | Strongest single confirmation, with no execution |
| Ran `upx -d -o C:\L\u\financials-xls_unpacked.exe C:\L\o\financials-xls.exe` | Unpack to a new file, leaving the original untouched | "Unpacked 1 file" | Approved unpack with traceable relationship between files |
| Hashed both files (19:07:57) | Prove the original is unchanged and record the unpacked identity | Original unchanged; unpacked SHA-256 `726A072434E751B2781D49F4F85EC213B60DF0EF6AA6377D5D55FAD0171E7DE9` | Traceability between original and unpacked |
| Compared sizes, DIE and pestudio on the unpacked file | Show what unpacking changed | See comparison below | Confirms packing was the cause of the earlier characteristics |

**Original vs unpacked**

| Characteristic | Original (packed) | Unpacked |
|---|---|---|
| Size | 43,520 bytes | 57,344 bytes |
| DIE detection | UPX(3.92)[NRV,best] | No packer reported (command line) |
| Sections | `UPX0` (raw 0), `UPX1`, `.rsrc` | `.text`, `.data`, `.rsrc` |
| Whole-file entropy (DIE) | 5.565 | 5.272 |
| Key section entropy | `UPX1` 7.844; PE header 6.985 | `.text` 6.388; PE header 2.049 |
| Imports (pestudio) | 10 (2 flagged: `VirtualProtect`, `sendto`) | 85 (20 flagged) |

After unpacking, the visible imports include registry functions (`RegCreateKeyExA`, `RegSetValueExA`, `RegDeleteKeyA`, `RegDeleteValueA`), `Shell_NotifyIconA`, window functions (`FindWindowA`, `FindWindowExA`, `GetDesktopWindow`) and socket functions (`connect`, `recvfrom`). These show what the program **could** do. They are static inferences, not observed behaviour.

**Assessment:** high confidence that the sample is UPX-packed. DIE (3.92), pestudio ("UPX 2.00-3.0X") and PE Detective ("UPX 2.90 [LZMA]") disagree on the exact version, so only "UPX" is asserted.

### Phase 3: Controlled runtime observation

| Action | Purpose | Result | Significance |
|---|---|---|---|
| Re-verified isolation with `VBoxManage showvminfo` and took snapshot `Lab02_PreExecution_ToolsReady` | Confirm controls were intact before execution | NIC 1 disabled, NIC 2 Host-only, clipboard and drag-and-drop disabled, no shared folders | Execution only proceeds if isolation is intact |
| Configured Regshot (plain TXT, output `C:\L\e`, directory scan off) | Prepare a registry before/after comparison | Ready; Compare not yet enabled | File scanning was off, so file results are not meaningful (limitation) |
| Saved an Autoruns baseline at 20:27 (`autoruns_before.arn`) | Record autostart state immediately before execution | Baseline saved | Reference for detecting new persistence |
| Started FakeNet-NG, Wireshark (capture file name timestamp 19:55:56), Process Monitor and Process Explorer | Capture network and process activity during the window | Monitoring active | Evidence collection began before execution |
| Executed the sample three times (about 20:49, 20:53, 20:57); run 3 launched with `$p = Start-Process C:\L\o\financials-xls.exe -PassThru` | Observe behaviour | Fake alert displayed; network requests logged on each run | Core dynamic observation |
| Recorded `$p.Id`, `StartTime`, `HasExited`, `ExitTime` | Capture the process identity and lifetime | PID 2868; start 20:57:10; exited 20:57:12 (about 2 s); no instance running at 22:08:54 | Establishes process identity for network correlation |
| Reviewed Process Monitor | Look for process and file activity | Filtered view (16,365 of 149,357 events) shows `powershell.exe` (PID 2488) opening the sample file; no rows attributed to the sample itself in the captured portion; log not saved | Parent is inferred, not proven; limits what can be claimed about file and process activity |
| Compared Autoruns (21:09) and exported Run keys (22:04) with `Compare-Object` | Detect persistence | Two new values under `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Direct evidence of Run-key persistence appearing during the window |
| Ran the Regshot comparison (21:09) | Quantify registry change | 721 total changes (96 keys added, 476 values added, 147 modified, 1 key and 1 value deleted) | Includes background Windows activity, so it is not attributed to the sample |
| Compared scheduled tasks | Look for task persistence | Visible output shows changed next-run times for existing tasks; no new task seen in the visible portion | Inconclusive rather than negative |

**Visible behaviour:** a toast titled `financials-xls.exe` reading "Your computer is infected! Windows has detected spyware infection! It is recommended to use special antispyware tools to prevent data loss." (text cut off on screen).

**Persistence values observed**

| Value name | Type | Data | Notes |
|---|---|---|---|
| `con` | REG_SZ | `C:\L\o\financials-xls.exe` | Points at the sample's own path; Autoruns shows the Excel icon and "Not Verified" |
| `Windows update loader` | REG_SZ | `C:\Windows\xpupdate.exe` | Different file name; existence of the target was not checked |

Both values were absent from the baselines (17:09 and 20:27) and present afterwards (21:09 and 22:04). The `con` value is strongly tied to the sample by its path. The `Windows update loader` value is tied to the sample by timing only. The process that wrote the values was not captured, so authorship is inferred.

### Phase 4: Network and behaviour correlation

| Time (VM) | Process (PID) | Destination | Request logged | Outcome |
|---|---|---|---|---|
| 20:49:00 | `financials-xls.exe` (1976) | TCP `69.50.175[.]181:80` | `GET /download.php?&advid=00000717&u=2884&p=47377624` HTTP/1.0, Host `download[.]bravesentry[.]com` | Accepted and logged by FakeNet-NG |
| 20:53:01 | `financials-xls.exe` (1600) | TCP `69.50.175[.]181:80` | `GET /download.php?&advid=00000717&u=4326&p=47246552` HTTP/1.0, same Host | Accepted and logged by FakeNet-NG |
| 20:57:11 | `financials-xls.exe` (2868) | TCP `69.50.175[.]181:80` | `GET /download.php?&advid=00000717&u=5768&p=47508696` HTTP/1.0, same Host | Accepted and logged by FakeNet-NG |

**Correlation and interpretation**

- The 20:57:11 request is attributed to **PID 2868**, which matches the PID recorded by PowerShell for run 3 (started 20:57:10, exited 20:57:12). Correlation is strong for run 3.
- Runs 1 and 2 (PIDs 1976 and 1600) have no launch evidence, so their attribution rests on the FakeNet-NG log alone.
- `advid` stays constant while `u` and `p` vary. Requests use HTTP/1.0 and show only a Host header in the listener log. The purpose of the parameters is unknown.
- Other log entries in the same window (`svchost.exe` name-resolution traffic, `MpDefenderCoreService.exe`, System NetBIOS broadcasts) are operating-system background traffic and were excluded.
- **DNS:** in the captured portion of the log (08:43:33 PM to 08:57:44 PM), no DNS query is attributed to the sample. The connection went directly to the IP address with the host name appearing only in the HTTP Host header, which is consistent with a hard-coded address. This rests on one log excerpt and the packet capture was not searched for it.
- **Packet capture:** `packets_20261001_195556.pcap` was preserved (1,383 KB, last written 9:10 PM). The single Wireshark view recorded (`tcp.stream eq 439`, 20:37:45) is FakeNet-NG's default web page from before the first run and is **not** sample traffic. Sample-specific filters were not applied.
- **Anti-analysis behaviour was not verified.** The unpacked import table includes `FindWindowA`/`FindWindowExA`, but that is only a static possibility with no runtime evidence.

**MITRE ATT&CK mapping**

| Technique | ID | Evidence | Confidence | Limitation |
|---|---|---|---|---|
| Obfuscated Files or Information: Software Packing | T1027.002 | DIE, pestudio, PE Detective, `upx -t` [OK], successful unpack | High | Static evidence; UPX is also used by legitimate software, so the mapping describes the technique, not intent |
| Application Layer Protocol: Web Protocols | T1071.001 | Three HTTP GETs to `69.50.175[.]181:80` | Medium | Server was simulated; purpose unknown |
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 | New HKCU Run values `con` and `Windows update loader` | Medium-High (`con`); Medium (`Windows update loader`) | Writer process not captured; three runs in the window; `xpupdate.exe` not verified |
| Masquerading | T1036 | Spreadsheet-style name with Excel icon; Run value named "Windows update loader" | Low-Medium | Based on naming and icon; delivery method unknown |

No technique is mapped for the fake alert (no fitting technique identified), for anti-analysis (no evidence) or for execution (the sample was run by the analyst, not by a delivery chain).

### Phase 5: Integrity, preservation and restoration

| Action | Purpose | Result | Significance |
|---|---|---|---|
| Re-hashed both files after the runs (completed 21:23:38) | Prove the sample did not alter itself | Original still `F09FFE74...5E5B5A`; unpacked still `726A0724...7DE9`; sizes unchanged | Integrity maintained through unpacking and three executions |
| Saved post-run files `a_net`, `a_ps`, `a_t` (21:29 to 21:30) and Run-key exports `a_u`, `a_m` (22:04) | Preserve the after-state | Files saved to `C:\L\e` | After-lists for processes and connections were captured but not analysed |
| Took snapshot `Lab02_PostExecution_Evidence` (host 10:06 PM) | Preserve the post-run state | Snapshot created | Evidence state preserved before restoration |
| Restored `Lab02_PreExecution_Baseline` (about 23:00 host time) | Return the VM to a clean state | Restore initiated; the capture shows it in progress | Safe closure of the exercise |

**Condensed timeline (VM clock unless noted)**

| Time | Event |
|---|---|
| 15:08 (host) | Baseline snapshot taken |
| 16:55:54 | Environment details recorded |
| 17:05 to 17:11 | Baselines saved |
| 17:16:37 | Original hashed |
| 18:07 to 18:47 | DIE, pestudio, PE Detective and `upx -t` on the original |
| about 19:06 | Approved unpack |
| 19:07:57 | Both files hashed |
| 19:55:56 | Packet capture started (from file name) |
| 20:27 | Autoruns baseline saved |
| 20:49:00 | Run 1 network event (PID 1976) |
| 20:53:01 | Run 2 network event (PID 1600) |
| 20:57:10 to 20:57:12 | Run 3 (PID 2868): alert shown, request at 20:57:11, exit |
| 21:09 | Regshot and Autoruns comparisons |
| 21:23:38 | Integrity re-check |
| 22:04:29 | Run-key comparison confirms two new values |
| about 23:00 (host) | Baseline snapshot restored |

---

## Findings

**Observed**

1. The file shows `UPX0`/`UPX1` sections, `UPX1` entropy of 7.844, a UPX signature and a passing `upx -t` test.
2. In run 3, the process (PID 2868) lived about two seconds, showed a fake spyware alert and exited by itself.
3. Each of three runs made one HTTP GET to `69.50.175[.]181:80` (Host `download[.]bravesentry[.]com`).
4. Two HKCU Run values appeared during the monitoring window.
5. The original file's hash was unchanged after unpacking and after execution.

**Inferred**

1. The binary unpacks itself at run time (standard UPX behaviour).
2. The alert is scareware meant to push the user toward "antispyware tools".
3. The GET is a check-in or download request to a remote server; its purpose is unknown.
4. Both Run values were written by the sample; authorship is not proven.
5. The unpacked imports (registry, shell notification, sockets) match the observed behaviour but are not proof of how it was achieved.

**Findings matrix**

| # | Finding | ATT&CK | Confidence | Limitation |
|---|---|---|---|---|
| 1 | Sample is UPX-packed | T1027.002 | High | Static; exact UPX version differs by tool |
| 2 | Original file unchanged by analysis | None | High | Hash covers file content only |
| 3 | Short-lived GUI process showing a fake spyware alert | None | High (observed, run 3) | Runs 1 and 2 have no launch evidence; intent is inferred |
| 4 | HTTP GET to a hard-coded IP, three times | T1071.001 | Medium (High that requests occurred) | Simulated server; purpose unknown |
| 5 | No DNS lookup by the sample observed | None | Low-Medium | One log excerpt; capture not searched |
| 6 | Run value `con` points to the sample | T1547.001 | Medium-High | Writer not captured; three runs in window |
| 7 | Run value `Windows update loader` points to `C:\Windows\xpupdate.exe` | T1547.001, T1036 | Medium | Link rests on timing; target not checked |
| 8 | Disguised as a spreadsheet and a Windows update | T1036 | Low-Medium | Delivery method unknown |
| 9 | Imports suggest registry, shell-notification and socket capability | None | Low | Static; partial import view |
| 10 | Anti-analysis checks | None | n/a | Not verified |
| 11 | File and process activity of the sample | None | n/a | Not established |

**Indicators of compromise** (network indicators defanged)

| Type | Value | Source | Timestamp (VM clock) |
|---|---|---|---|
| File name / size | `financials-xls.exe`, 43,520 bytes | File listing | 17:15 |
| SHA-256 (packed) | `F09FFE74770A7229DDEF667BC95FA73E0886ADF8739CDFFF36101443975E5B5A` | `Get-FileHash`, pestudio | 17:16:37; 19:07:57; 21:23:38 |
| SHA-256 (unpacked) | `726A072434E751B2781D49F4F85EC213B60DF0EF6AA6377D5D55FAD0171E7DE9` | `Get-FileHash`, pestudio | 19:07:57 |
| Imphash (MD5, packed) | `4A5EBEC485BEB64F91EDF76F986F8113` | pestudio | 18:39 |
| IP and port | `69.50.175[.]181:80/TCP` | FakeNet-NG Diverter log | 20:49:00; 20:53:01; 20:57:11 |
| HTTP Host | `download[.]bravesentry[.]com` | FakeNet-NG HTTP listener | 20:49:00; 20:53:01; 20:57:11 |
| URI pattern | `/download.php?&advid=00000717&u=<varies>&p=<varies>` (HTTP/1.0 GET) | FakeNet-NG HTTP listener | 20:49:00; 20:53:01; 20:57:11 |
| Registry | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\con` = `C:\L\o\financials-xls.exe` (path reflects the analysis location) | Autoruns, `Compare-Object` | 21:09; 22:04:29 |
| Registry | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Windows update loader` = `C:\Windows\xpupdate.exe` | Autoruns, `Compare-Object` | 21:09; 22:04:29 |
| On-screen text | "Your computer is infected! Windows has detected spyware infection!" | Observed alert | 20:57 |

Weaker details are deliberately **not** listed as indicators: the PE compile stamp (7 May 2007) and Russian resource language come from a packed file and are easy to alter, and the process IDs and `u`/`p` values vary per run.

---

## Challenges Encountered

Recording these openly is part of the method. None changes the conclusions, but each limits what can be claimed.

| Challenge | What happened | Effect |
|---|---|---|
| Process Monitor log not saved | Procmon ran during execution but no log file was preserved | Process tree, the sample's own file and registry operations, the writer of the Run values and anti-analysis checks are unverified |
| Three runs in one window | Only run 3 has launch and exit evidence | Registry and autostart changes cannot be tied to a single run |
| Simulated server | FakeNet-NG answered all requests | Real server behaviour, response content and any second-stage payload are unknown |
| Regshot file scan off; no saved process baseline | Directory scanning was disabled and `b_ps.txt` was not saved | File results are not meaningful; no saved process baseline |
| Tool availability | `diec` not on PATH; PE-bear not installed | Resolved by calling DIE by full path and using pestudio for sections and imports |
| Mistyped commands | `gGet-FileHash`, `finacials-xls.exe`, and two Ctrl+C interruptions | Commands re-run correctly and recorded |
| Exit code not captured | `$p.ExitCode` was typed in a tab where `$p` was undefined | Exit confirmed instead by `HasExited` and `ExitTime` |
| Unrelated Wireshark stream | `tcp.stream eq 439` shows FakeNet-NG's default page from before the first run | Not used as sample evidence |
| Optional checks not performed | Existence of `xpupdate.exe`, a name-only task comparison and sample-specific Wireshark filters | Listed as limitations |
| Snapshot timing | `Lab02_PreExecution_ToolsReady` is time-stamped 9:04 PM (host), later than the recorded runs (20:49 to 20:57). No evidence compares the host and VM clocks, though the post-run snapshot timing suggests they agree within a few minutes | The snapshot is not relied on as a pre-execution restore point; the clean baseline is `Lab02_PreExecution_Baseline` |
| Baseline timing | The baseline snapshot precedes folder creation and extraction, but the time the archive reached the VM was not recorded | No claim is made about the archive download |

---

## Recommendations

**Improvements to the analysis process (drawn from the limitations above)**

1. Save the Process Monitor capture (`.pml`) to the evidence folder immediately after each run.
2. Execute one run per snapshot restore so changes can be attributed to a single execution.
3. Capture the process baseline to a file (`b_ps.txt`) along with the other baselines.
4. Enable Regshot directory scanning for the paths of interest, and record a host-versus-VM clock comparison at the start.
5. Apply sample-specific filters in Wireshark (destination IP, `download.php`, DNS for the Host name) and search the capture for DNS activity.
6. Check whether `C:\Windows\xpupdate.exe` exists and record its metadata and SHA-256; run a name-only scheduled-task comparison.

**Defensive use of the findings (derived from the observed indicators; not tested in a production environment)**

1. Search endpoint telemetry for the SHA-256 values and imphash listed above.
2. Look for new `HKCU\...\CurrentVersion\Run` values named `con` or `Windows update loader`, or values pointing at `C:\Windows\xpupdate.exe`.
3. Search proxy and network logs for HTTP requests to `/download.php` containing `advid=00000717`, and for traffic to `69.50.175[.]181`.

---

## Key Learning Outcomes

- Designing and proving an isolated dynamic-analysis environment before any execution.
- Establishing and maintaining evidence integrity with hashes, snapshots and separate working folders.
- Demonstrating packing from several independent angles, and understanding why whole-file entropy alone can mislead.
- Safely unpacking a sample with the packer's own workflow and keeping both versions traceable.
- Using simulated network services to capture communication attempts safely and correlating them with process IDs.
- Distinguishing observation from inference, assigning confidence levels, and mapping to MITRE ATT&CK only where evidence supports it.
- Recording errors, gaps and limitations openly instead of smoothing them over.

---

## Professional Value

This project demonstrates, with evidence, that the author can:

- **Run a malware analysis safely and methodically**, from isolation proof through restoration.
- **Combine static and dynamic analysis** to move from "this file looks packed" to "this is what it did".
- **Correlate network, process and registry evidence** to build a defensible narrative.
- **Produce usable indicators** (hashes, imphash, network indicators, registry values) with sources and timestamps.
- **Communicate with calibrated confidence**, naming limitations and unverified areas instead of overstating results.
- **Keep disciplined evidence records** that another analyst could follow and verify.

---

## Conclusion

`financials-xls.exe` is a UPX-packed 32-bit Windows GUI executable. Static analysis and a successful unpack give high confidence in the packing result. In three executions inside a Host-only VM with simulated services, the sample ran for about two seconds, displayed a fake spyware-infection alert and sent an HTTP GET to the hard-coded address `69.50.175[.]181:80`, requesting `/download.php` with a constant `advid` and varying `u` and `p` parameters. Two HKCU Run values appeared during the monitoring window: one pointing at the sample's own path and one pointing at `C:\Windows\xpupdate.exe`.

The most likely capability is a scareware or rogue-security-style program that contacts a remote server and sets up Run-key persistence. Confidence is **medium** overall: high for packing, the alert and the network requests, medium to medium-high for persistence, and **low** for what any downloaded payload might do, because the server was simulated. File activity, the full process tree and anti-analysis behaviour remain unverified and are documented as limitations.

---

## Repository Structure

```text
.
├── README.md                              # This document
├── report/
│   └── Technical_Report.docx              # Full technical report
├── evidence-log/
│   └── evidence_log.csv                   # Chronological evidence log
└── iocs/
    └── iocs.md                            # Optional: indicators from this README (defanged)
```

The malware sample and its unpacked copy are intentionally **not** stored in this repository. Screenshots captured during the exercise are not published here; they are referenced by the technical report and the evidence log.

---

## Responsible AI Use Declaration

An AI assistant (Claude, by Anthropic) # Dynamic Malware Analysis of a UPX-Packed Windows Executable

**Controlled static and dynamic analysis of a packed 32-bit Windows sample (`financials-xls.exe`) in an isolated FLARE-VM lab, with evidence-based findings, IOCs and MITRE ATT&CK mapping.**

| | |
|---|---|
| **Author** | [Your Name] |
| **Focus** | Malware analysis, dynamic analysis, evidence handling, network correlation, technical reporting |
| **Environment** | VirtualBox, FLARE-VM (Windows 11), Host-only network with FakeNet-NG simulated services |
| **Analysis date** | 1 October 2026 (VM clock) |
| **Overall confidence** | High (packing, alert, network requests); Medium (persistence, likely capability); Low (any downloaded payload) |

> **Safety note:** All analysis was performed inside an isolated virtual machine with no Internet access. The malware sample is **not** included in this repository. All network indicators below are **defanged** (`[.]`) so they cannot be clicked or resolved by accident.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Executive Summary](#executive-summary)
3. [Objectives](#objectives)
4. [Skills Demonstrated](#skills-demonstrated)
5. [Technologies and Tools Used](#technologies-and-tools-used)
6. [Lab Environment](#lab-environment)
7. [Methodology](#methodology)
8. [Evidence and Analysis](#evidence-and-analysis)
9. [Findings](#findings)
10. [Challenges Encountered](#challenges-encountered)
11. [Recommendations](#recommendations)
12. [Key Learning Outcomes](#key-learning-outcomes)
13. [Professional Value](#professional-value)
14. [Conclusion](#conclusion)
15. [Repository Structure](#repository-structure)
16. [Responsible AI Use Declaration](#responsible-ai-use-declaration)
17. [Disclaimer](#disclaimer)
18. [References, Attribution and Acknowledgements](#references-attribution-and-acknowledgements)

---

## Project Overview

This project documents a complete malware-analysis workflow against a course-provided Windows executable named `financials-xls.exe`. The sample was treated as untrusted code from the first step: the environment was isolated and baselined before anything was run, the file was hashed and verified at every stage, packing was proven with independent evidence before the file was unpacked, and the sample was executed only under active monitoring.

The goal was not only to find out what the sample does, but to **separate what was observed from what was inferred**, to state confidence levels, and to be explicit about what the evidence could not show.

**Scenario in one paragraph:** a file named like a spreadsheet and carrying an Excel icon turned out to be a UPX-packed GUI program that shows a fake spyware-infection alert, contacts a hard-coded IP address over HTTP, and adds Run-key persistence entries.

---

## Executive Summary

`financials-xls.exe` is a 43,520-byte, 32-bit Windows GUI executable packed with UPX. Four independent checks (signature detection, section and entropy structure, UPX's own integrity test and a successful unpack) support the packing conclusion with **high confidence**. Unpacking produced a 57,344-byte file with a conventional section layout, lower entropy and an import table of 85 functions instead of 10.

The sample was executed three times in one monitoring window (20:49 to 20:57 VM time) on a Host-only network with simulated Internet services. In the one run captured end to end (PID 2868), it started at 20:57:10, displayed a fake "Your computer is infected!" alert and exited by itself at 20:57:12. On every run it sent one HTTP GET to a hard-coded address (`69.50.175[.]181:80`, `/download.php`, Host `download[.]bravesentry[.]com`). Two new `HKCU\...\Run` values appeared during the window: one pointing at the sample itself and one pointing at `C:\Windows\xpupdate.exe`.

**Likely capability:** a scareware or rogue-security-style program that contacts a remote server and sets up Run-key persistence. Confidence is **medium** overall and **low** for anything a downloaded payload might do, because the server was simulated.

**Key results**

| Area | Result | Confidence |
|---|---|---|
| Packing | UPX packed; unpacked from 43,520 to 57,344 bytes | High |
| Process behaviour | Run 3: PID 2868, lifetime about 2 s, fake spyware alert, self-exit | High (run 3); Medium (runs 1 and 2) |
| Network | Three HTTP GETs to `69.50.175[.]181:80`, intercepted by FakeNet-NG | High that requests occurred; Low on purpose |
| Persistence | Two new HKCU Run values | Medium-High (`con`); Medium (`Windows update loader`) |
| Not established | File activity, full process tree, anti-analysis behaviour, existence of `xpupdate.exe` | Stated as limitations |

---

## Objectives

1. Build a safe dynamic-analysis environment and prove its isolation controls before handling the sample.
2. Record an evidence baseline (processes, connections, startup locations, scheduled tasks, hash of the original file).
3. Confirm UPX packing with independent tools, unpack the sample without executing it, and keep the original and unpacked files traceable by hash.
4. Observe the sample under monitoring and record process, file, registry and persistence activity that is directly visible in the evidence.
5. Capture attempted network communication safely and correlate it with the responsible process and timestamp.
6. Map supported observations to MITRE ATT&CK with confidence levels, extract indicators of compromise, and state limitations clearly.

---

## Skills Demonstrated

Only skills supported by the work in this project are listed.

| Skill area | How it was demonstrated |
|---|---|
| **Malware analysis (static)** | Identified UPX packing using signature detection, section layout, per-section entropy, import analysis and the packer's own integrity test; unpacked the file safely and compared both versions |
| **Malware analysis (dynamic)** | Executed the sample under monitoring and recorded its process, visible behaviour, registry persistence and network activity |
| **Network analysis** | Interpreted FakeNet-NG connection logs, identified destination, port, protocol, HTTP request structure and URI pattern, and correlated each connection to a process ID |
| **Log analysis** | Read and filtered FakeNet-NG log output to separate sample traffic from operating-system background traffic |
| **Digital forensics practice** | SHA-256 hashing before, during and after analysis; snapshot-based restore points; separate folders for original, unpacked and evidence files; chronological evidence log |
| **Indicator extraction and threat mapping** | Produced an IOC table with sources and timestamps and mapped observations to MITRE ATT&CK with confidence levels |
| **Lab safety and isolation** | Verified Host-only networking, disabled clipboard, drag-and-drop and shared folders, and used simulated services so no traffic left the lab |
| **Documentation and reporting** | Kept a timestamped evidence log, separated observed facts from inference, and recorded errors, deviations and limitations openly |

**Not part of this project:** SIEM investigation, vulnerability assessment, threat hunting across an environment, and live incident response were not performed and are not claimed.

---

## Technologies and Tools Used

| Tool | Version / detail | Purpose |
|---|---|---|
| Oracle VirtualBox / VBoxManage | Host | VM isolation proof and snapshots |
| FLARE-VM on Windows 11 | Build 10.0.22621.1555 | Analysis workstation |
| Windows PowerShell | Guest | Baselines, hashing, execution, comparisons |
| UPX | 5.2.0 | Packing test (`-t`, `-l`) and unpacking (`-d -o`) |
| Detect It Easy (DIE) | v3.10 | Packer signature, entropy, sections |
| pestudio | 9.61 | Sections, entropy, imports, indicators |
| PE Detective | Deep scan | Independent packer-signature check |
| Process Monitor, Process Explorer | Sysinternals | Process and file monitoring during execution |
| Regshot | 1.9.1 x64 Unicode | Registry before/after comparison |
| Autoruns | Sysinternals | Autostart baseline and comparison |
| FakeNet-NG | 3.5 | Simulated network services and per-process connection logging |
| Wireshark | Capture file saved | Packet capture |

PE-bear was not installed in this build. PE Carve was present but deliberately not used, because it extracts embedded content and could alter the evidence set.

---

## Lab Environment

**Isolation controls (verified from the host with `VBoxManage showvminfo` and the VirtualBox interface)**

| Control | State |
|---|---|
| Network | Host-only only (NIC 2); NIC 1 and NICs 3 to 8 disabled |
| Internet access | None; services simulated inside the guest by FakeNet-NG |
| Shared clipboard (including file transfers) | Disabled |
| Drag and drop | Disabled |
| Shared folders | None |
| USB | xHCI controller enabled, but no filters and no attached devices |

**Environment record**

| Item | Value |
|---|---|
| VM name / guest hostname | `windows11` / `flare` |
| Guest OS | Windows 11 64-bit, `10.0.22621.1555` |
| Resources | 8192 MB RAM, 2 CPUs, 97.01 GB disk |
| Working folders | `C:\L\o` (original), `C:\L\u` (unpacked), `C:\L\e` (evidence) |

**Snapshot chain (host clock)**

| Snapshot | Taken | Role |
|---|---|---|
| `win11` | 9/29/2026 7:59 PM | Base FLARE-VM state |
| `Snapshot 2` | 9/30/2026 12:02 AM | Intermediate preparation state |
| `Lab02_PreExecution_Baseline` | 10/1/2026 3:08 PM | Clean baseline; restore target |
| `Lab02_PreExecution_ToolsReady` | 10/1/2026 9:04 PM | Tools-ready state (see timing caveat under [Challenges](#challenges-encountered)) |
| `Lab02_PostExecution_Evidence` | 10/1/2026 10:06 PM | Post-run evidence preserved |

---

## Methodology

The work followed five phases. Each phase produced evidence that the next phase depended on.

| Phase | What was done | Why it matters |
|---|---|---|
| **1. Environment preparation** | Verified isolation, took a clean snapshot, recorded environment details and baselines, hashed the original sample | Makes later claims defensible: "this value was not there before" and "this file is the one I started with" |
| **2. Packing validation and unpacking** | Checked UPX indicators with several tools, unpacked to a new filename, hashed both files, compared them | Shows how a conclusion was reached instead of assuming it |
| **3. Controlled runtime observation** | Started monitoring, executed the sample, recorded process, registry and startup changes | Turns static suspicion into observed behaviour |
| **4. Network and behaviour correlation** | Logged connection attempts with FakeNet-NG and matched them to process IDs and timestamps | Links network activity to the responsible process |
| **5. Findings and restoration** | Built the findings matrix, IOCs and ATT&CK mapping, re-verified file integrity, restored the clean snapshot | Closes the loop and leaves the lab in a known-good state |

---

## Evidence and Analysis

> Timestamps in PowerShell evidence are the FLARE prompt times (when each prompt was drawn), so a command was entered at or shortly after that time. "Host" times come from the VirtualBox interface.

### Phase 1: Environment preparation

| Action | Purpose | Result | Significance |
|---|---|---|---|
| Ran `VBoxManage showvminfo "windows11"` filtered for clipboard, drag-and-drop, NIC, shared folder and USB lines (first attempt returned a `FindMachine` error and was re-run with the correct VM name) | Prove isolation from configuration data rather than from memory | NIC 1 and 3 to 8 disabled; NIC 2 Host-only; clipboard, file transfers and drag-and-drop disabled; no shared folders; xHCI enabled with no devices | Configuration-level proof that nothing could cross the VM boundary except Host-only traffic |
| Reviewed VirtualBox Manager details and Settings | Provide a second, visual confirmation | Windows 11 64-bit, 8192 MB, 2 CPUs; Adapter 2 Host-only; clipboard and drag-and-drop Disabled | Confirms the same controls through the GUI |
| Took snapshot `Lab02_PreExecution_Baseline` (host 3:08 PM) | Create a clean restore point | Snapshot created, taken before the working folders (4:52 PM) and the extracted sample (5:15 PM) existed | Allows rollback after execution. The time the archive reached the VM was not recorded, so no claim is made about it |
| Created `C:\L\o` and `C:\L\e`; ran `hostname; cmd /c ver; date` | Separate evidence by type and record the environment and time reference | Host `flare`; Windows `10.0.22621.1555`; 4:55:54 PM on 1 October 2026 | Establishes the environment record and the VM time reference |
| Captured baselines: `netstat -ano`, `reg query` on HKCU and HKLM Run keys, `schtasks` (saved as `b_net`, `b_u`, `b_m`, `b_t`, 17:05 to 17:11) | Record the "before" state | Four baseline files saved. The process list was shown on screen but `b_ps.txt` was not saved | Enables before/after comparison; the missing process baseline is recorded as a limitation |
| Confirmed the sample sat in `C:\L\o` (43,520 bytes, file-system date 2/7/2018 12:55 AM) without executing it | Verify extraction without execution | File present, size matches later tool output | Start of chain of custody |
| Ran `Get-FileHash` on the original (17:16:37; first attempt mistyped and re-run) | Fix the file's identity before any further action | SHA-256 `F09FFE74770A7229DDEF667BC95FA73E0886ADF8739CDFFF36101443975E5B5A` | A fixed fingerprint that later hashes are compared against |

### Phase 2: Packing validation and approved unpacking

| Action | Purpose | Result | Significance |
|---|---|---|---|
| Checked tools with `upx -V` and `where.exe`; located DIE with `gci` | Confirm approved tools exist | UPX 5.2.0; `diec` not on PATH; DIE found in `C:\Tools\die` and called by full path | Documented tool gap, resolved without changing the method |
| Scanned the original with DIE (command line and GUI) | Identify the packer by signature | `Packer: UPX(3.92)[NRV,best]`; GUI also raised a heuristic "compressed or packed data" detection | First independent indicator |
| Reviewed DIE entropy and sections | Measure compression statistically | Whole-file entropy 5.565 (DIE summary reads "not packed 69%"); per-region: PE header 6.985, `UPX1` 7.844, both marked "packed" | Shows why per-section entropy is the correct measure: the low-entropy `.rsrc` dilutes the whole-file average |
| Inspected the original in pestudio | Cross-check structure and imports | Sections `UPX0` (raw size 0, virtual size 57,344), `UPX1` (14,848 bytes, entropy 7.844), `.rsrc` (27,648 bytes, entropy 3.470); entry point `0x00012790` inside `UPX1`; `UPX0`/`UPX1` flagged self-modifying; 10 imports | Matches the classic UPX layout: empty section to decompress into, compressed section holding the stub, few visible imports |
| Ran PE Detective deep scan | Third method: signature families | Three UPX signature families matched; best match "UPX 2.90 [LZMA] (Delphi stub)" | Agreement on UPX; disagreement on version is noted |
| Ran `upx -t` and `upx -l` | Let the packer verify itself without writing or executing | `[OK]`; 57,344 unpacked vs 43,520 packed (75.89%) | Strongest single confirmation, with no execution |
| Ran `upx -d -o C:\L\u\financials-xls_unpacked.exe C:\L\o\financials-xls.exe` | Unpack to a new file, leaving the original untouched | "Unpacked 1 file" | Approved unpack with traceable relationship between files |
| Hashed both files (19:07:57) | Prove the original is unchanged and record the unpacked identity | Original unchanged; unpacked SHA-256 `726A072434E751B2781D49F4F85EC213B60DF0EF6AA6377D5D55FAD0171E7DE9` | Traceability between original and unpacked |
| Compared sizes, DIE and pestudio on the unpacked file | Show what unpacking changed | See comparison below | Confirms packing was the cause of the earlier characteristics |

**Original vs unpacked**

| Characteristic | Original (packed) | Unpacked |
|---|---|---|
| Size | 43,520 bytes | 57,344 bytes |
| DIE detection | UPX(3.92)[NRV,best] | No packer reported (command line) |
| Sections | `UPX0` (raw 0), `UPX1`, `.rsrc` | `.text`, `.data`, `.rsrc` |
| Whole-file entropy (DIE) | 5.565 | 5.272 |
| Key section entropy | `UPX1` 7.844; PE header 6.985 | `.text` 6.388; PE header 2.049 |
| Imports (pestudio) | 10 (2 flagged: `VirtualProtect`, `sendto`) | 85 (20 flagged) |

After unpacking, the visible imports include registry functions (`RegCreateKeyExA`, `RegSetValueExA`, `RegDeleteKeyA`, `RegDeleteValueA`), `Shell_NotifyIconA`, window functions (`FindWindowA`, `FindWindowExA`, `GetDesktopWindow`) and socket functions (`connect`, `recvfrom`). These show what the program **could** do. They are static inferences, not observed behaviour.

**Assessment:** high confidence that the sample is UPX-packed. DIE (3.92), pestudio ("UPX 2.00-3.0X") and PE Detective ("UPX 2.90 [LZMA]") disagree on the exact version, so only "UPX" is asserted.

### Phase 3: Controlled runtime observation

| Action | Purpose | Result | Significance |
|---|---|---|---|
| Re-verified isolation with `VBoxManage showvminfo` and took snapshot `Lab02_PreExecution_ToolsReady` | Confirm controls were intact before execution | NIC 1 disabled, NIC 2 Host-only, clipboard and drag-and-drop disabled, no shared folders | Execution only proceeds if isolation is intact |
| Configured Regshot (plain TXT, output `C:\L\e`, directory scan off) | Prepare a registry before/after comparison | Ready; Compare not yet enabled | File scanning was off, so file results are not meaningful (limitation) |
| Saved an Autoruns baseline at 20:27 (`autoruns_before.arn`) | Record autostart state immediately before execution | Baseline saved | Reference for detecting new persistence |
| Started FakeNet-NG, Wireshark (capture file name timestamp 19:55:56), Process Monitor and Process Explorer | Capture network and process activity during the window | Monitoring active | Evidence collection began before execution |
| Executed the sample three times (about 20:49, 20:53, 20:57); run 3 launched with `$p = Start-Process C:\L\o\financials-xls.exe -PassThru` | Observe behaviour | Fake alert displayed; network requests logged on each run | Core dynamic observation |
| Recorded `$p.Id`, `StartTime`, `HasExited`, `ExitTime` | Capture the process identity and lifetime | PID 2868; start 20:57:10; exited 20:57:12 (about 2 s); no instance running at 22:08:54 | Establishes process identity for network correlation |
| Reviewed Process Monitor | Look for process and file activity | Filtered view (16,365 of 149,357 events) shows `powershell.exe` (PID 2488) opening the sample file; no rows attributed to the sample itself in the captured portion; log not saved | Parent is inferred, not proven; limits what can be claimed about file and process activity |
| Compared Autoruns (21:09) and exported Run keys (22:04) with `Compare-Object` | Detect persistence | Two new values under `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Direct evidence of Run-key persistence appearing during the window |
| Ran the Regshot comparison (21:09) | Quantify registry change | 721 total changes (96 keys added, 476 values added, 147 modified, 1 key and 1 value deleted) | Includes background Windows activity, so it is not attributed to the sample |
| Compared scheduled tasks | Look for task persistence | Visible output shows changed next-run times for existing tasks; no new task seen in the visible portion | Inconclusive rather than negative |

**Visible behaviour:** a toast titled `financials-xls.exe` reading "Your computer is infected! Windows has detected spyware infection! It is recommended to use special antispyware tools to prevent data loss." (text cut off on screen).

**Persistence values observed**

| Value name | Type | Data | Notes |
|---|---|---|---|
| `con` | REG_SZ | `C:\L\o\financials-xls.exe` | Points at the sample's own path; Autoruns shows the Excel icon and "Not Verified" |
| `Windows update loader` | REG_SZ | `C:\Windows\xpupdate.exe` | Different file name; existence of the target was not checked |

Both values were absent from the baselines (17:09 and 20:27) and present afterwards (21:09 and 22:04). The `con` value is strongly tied to the sample by its path. The `Windows update loader` value is tied to the sample by timing only. The process that wrote the values was not captured, so authorship is inferred.

### Phase 4: Network and behaviour correlation

| Time (VM) | Process (PID) | Destination | Request logged | Outcome |
|---|---|---|---|---|
| 20:49:00 | `financials-xls.exe` (1976) | TCP `69.50.175[.]181:80` | `GET /download.php?&advid=00000717&u=2884&p=47377624` HTTP/1.0, Host `download[.]bravesentry[.]com` | Accepted and logged by FakeNet-NG |
| 20:53:01 | `financials-xls.exe` (1600) | TCP `69.50.175[.]181:80` | `GET /download.php?&advid=00000717&u=4326&p=47246552` HTTP/1.0, same Host | Accepted and logged by FakeNet-NG |
| 20:57:11 | `financials-xls.exe` (2868) | TCP `69.50.175[.]181:80` | `GET /download.php?&advid=00000717&u=5768&p=47508696` HTTP/1.0, same Host | Accepted and logged by FakeNet-NG |

**Correlation and interpretation**

- The 20:57:11 request is attributed to **PID 2868**, which matches the PID recorded by PowerShell for run 3 (started 20:57:10, exited 20:57:12). Correlation is strong for run 3.
- Runs 1 and 2 (PIDs 1976 and 1600) have no launch evidence, so their attribution rests on the FakeNet-NG log alone.
- `advid` stays constant while `u` and `p` vary. Requests use HTTP/1.0 and show only a Host header in the listener log. The purpose of the parameters is unknown.
- Other log entries in the same window (`svchost.exe` name-resolution traffic, `MpDefenderCoreService.exe`, System NetBIOS broadcasts) are operating-system background traffic and were excluded.
- **DNS:** in the captured portion of the log (08:43:33 PM to 08:57:44 PM), no DNS query is attributed to the sample. The connection went directly to the IP address with the host name appearing only in the HTTP Host header, which is consistent with a hard-coded address. This rests on one log excerpt and the packet capture was not searched for it.
- **Packet capture:** `packets_20261001_195556.pcap` was preserved (1,383 KB, last written 9:10 PM). The single Wireshark view recorded (`tcp.stream eq 439`, 20:37:45) is FakeNet-NG's default web page from before the first run and is **not** sample traffic. Sample-specific filters were not applied.
- **Anti-analysis behaviour was not verified.** The unpacked import table includes `FindWindowA`/`FindWindowExA`, but that is only a static possibility with no runtime evidence.

**MITRE ATT&CK mapping**

| Technique | ID | Evidence | Confidence | Limitation |
|---|---|---|---|---|
| Obfuscated Files or Information: Software Packing | T1027.002 | DIE, pestudio, PE Detective, `upx -t` [OK], successful unpack | High | Static evidence; UPX is also used by legitimate software, so the mapping describes the technique, not intent |
| Application Layer Protocol: Web Protocols | T1071.001 | Three HTTP GETs to `69.50.175[.]181:80` | Medium | Server was simulated; purpose unknown |
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 | New HKCU Run values `con` and `Windows update loader` | Medium-High (`con`); Medium (`Windows update loader`) | Writer process not captured; three runs in the window; `xpupdate.exe` not verified |
| Masquerading | T1036 | Spreadsheet-style name with Excel icon; Run value named "Windows update loader" | Low-Medium | Based on naming and icon; delivery method unknown |

No technique is mapped for the fake alert (no fitting technique identified), for anti-analysis (no evidence) or for execution (the sample was run by the analyst, not by a delivery chain).

### Phase 5: Integrity, preservation and restoration

| Action | Purpose | Result | Significance |
|---|---|---|---|
| Re-hashed both files after the runs (completed 21:23:38) | Prove the sample did not alter itself | Original still `F09FFE74...5E5B5A`; unpacked still `726A0724...7DE9`; sizes unchanged | Integrity maintained through unpacking and three executions |
| Saved post-run files `a_net`, `a_ps`, `a_t` (21:29 to 21:30) and Run-key exports `a_u`, `a_m` (22:04) | Preserve the after-state | Files saved to `C:\L\e` | After-lists for processes and connections were captured but not analysed |
| Took snapshot `Lab02_PostExecution_Evidence` (host 10:06 PM) | Preserve the post-run state | Snapshot created | Evidence state preserved before restoration |
| Restored `Lab02_PreExecution_Baseline` (about 23:00 host time) | Return the VM to a clean state | Restore initiated; the capture shows it in progress | Safe closure of the exercise |

**Condensed timeline (VM clock unless noted)**

| Time | Event |
|---|---|
| 15:08 (host) | Baseline snapshot taken |
| 16:55:54 | Environment details recorded |
| 17:05 to 17:11 | Baselines saved |
| 17:16:37 | Original hashed |
| 18:07 to 18:47 | DIE, pestudio, PE Detective and `upx -t` on the original |
| about 19:06 | Approved unpack |
| 19:07:57 | Both files hashed |
| 19:55:56 | Packet capture started (from file name) |
| 20:27 | Autoruns baseline saved |
| 20:49:00 | Run 1 network event (PID 1976) |
| 20:53:01 | Run 2 network event (PID 1600) |
| 20:57:10 to 20:57:12 | Run 3 (PID 2868): alert shown, request at 20:57:11, exit |
| 21:09 | Regshot and Autoruns comparisons |
| 21:23:38 | Integrity re-check |
| 22:04:29 | Run-key comparison confirms two new values |
| about 23:00 (host) | Baseline snapshot restored |

---

## Findings

**Observed**

1. The file shows `UPX0`/`UPX1` sections, `UPX1` entropy of 7.844, a UPX signature and a passing `upx -t` test.
2. In run 3, the process (PID 2868) lived about two seconds, showed a fake spyware alert and exited by itself.
3. Each of three runs made one HTTP GET to `69.50.175[.]181:80` (Host `download[.]bravesentry[.]com`).
4. Two HKCU Run values appeared during the monitoring window.
5. The original file's hash was unchanged after unpacking and after execution.

**Inferred**

1. The binary unpacks itself at run time (standard UPX behaviour).
2. The alert is scareware meant to push the user toward "antispyware tools".
3. The GET is a check-in or download request to a remote server; its purpose is unknown.
4. Both Run values were written by the sample; authorship is not proven.
5. The unpacked imports (registry, shell notification, sockets) match the observed behaviour but are not proof of how it was achieved.

**Findings matrix**

| # | Finding | ATT&CK | Confidence | Limitation |
|---|---|---|---|---|
| 1 | Sample is UPX-packed | T1027.002 | High | Static; exact UPX version differs by tool |
| 2 | Original file unchanged by analysis | None | High | Hash covers file content only |
| 3 | Short-lived GUI process showing a fake spyware alert | None | High (observed, run 3) | Runs 1 and 2 have no launch evidence; intent is inferred |
| 4 | HTTP GET to a hard-coded IP, three times | T1071.001 | Medium (High that requests occurred) | Simulated server; purpose unknown |
| 5 | No DNS lookup by the sample observed | None | Low-Medium | One log excerpt; capture not searched |
| 6 | Run value `con` points to the sample | T1547.001 | Medium-High | Writer not captured; three runs in window |
| 7 | Run value `Windows update loader` points to `C:\Windows\xpupdate.exe` | T1547.001, T1036 | Medium | Link rests on timing; target not checked |
| 8 | Disguised as a spreadsheet and a Windows update | T1036 | Low-Medium | Delivery method unknown |
| 9 | Imports suggest registry, shell-notification and socket capability | None | Low | Static; partial import view |
| 10 | Anti-analysis checks | None | n/a | Not verified |
| 11 | File and process activity of the sample | None | n/a | Not established |

**Indicators of compromise** (network indicators defanged)

| Type | Value | Source | Timestamp (VM clock) |
|---|---|---|---|
| File name / size | `financials-xls.exe`, 43,520 bytes | File listing | 17:15 |
| SHA-256 (packed) | `F09FFE74770A7229DDEF667BC95FA73E0886ADF8739CDFFF36101443975E5B5A` | `Get-FileHash`, pestudio | 17:16:37; 19:07:57; 21:23:38 |
| SHA-256 (unpacked) | `726A072434E751B2781D49F4F85EC213B60DF0EF6AA6377D5D55FAD0171E7DE9` | `Get-FileHash`, pestudio | 19:07:57 |
| Imphash (MD5, packed) | `4A5EBEC485BEB64F91EDF76F986F8113` | pestudio | 18:39 |
| IP and port | `69.50.175[.]181:80/TCP` | FakeNet-NG Diverter log | 20:49:00; 20:53:01; 20:57:11 |
| HTTP Host | `download[.]bravesentry[.]com` | FakeNet-NG HTTP listener | 20:49:00; 20:53:01; 20:57:11 |
| URI pattern | `/download.php?&advid=00000717&u=<varies>&p=<varies>` (HTTP/1.0 GET) | FakeNet-NG HTTP listener | 20:49:00; 20:53:01; 20:57:11 |
| Registry | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\con` = `C:\L\o\financials-xls.exe` (path reflects the analysis location) | Autoruns, `Compare-Object` | 21:09; 22:04:29 |
| Registry | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Windows update loader` = `C:\Windows\xpupdate.exe` | Autoruns, `Compare-Object` | 21:09; 22:04:29 |
| On-screen text | "Your computer is infected! Windows has detected spyware infection!" | Observed alert | 20:57 |

Weaker details are deliberately **not** listed as indicators: the PE compile stamp (7 May 2007) and Russian resource language come from a packed file and are easy to alter, and the process IDs and `u`/`p` values vary per run.

---

## Challenges Encountered

Recording these openly is part of the method. None changes the conclusions, but each limits what can be claimed.

| Challenge | What happened | Effect |
|---|---|---|
| Process Monitor log not saved | Procmon ran during execution but no log file was preserved | Process tree, the sample's own file and registry operations, the writer of the Run values and anti-analysis checks are unverified |
| Three runs in one window | Only run 3 has launch and exit evidence | Registry and autostart changes cannot be tied to a single run |
| Simulated server | FakeNet-NG answered all requests | Real server behaviour, response content and any second-stage payload are unknown |
| Regshot file scan off; no saved process baseline | Directory scanning was disabled and `b_ps.txt` was not saved | File results are not meaningful; no saved process baseline |
| Tool availability | `diec` not on PATH; PE-bear not installed | Resolved by calling DIE by full path and using pestudio for sections and imports |
| Mistyped commands | `gGet-FileHash`, `finacials-xls.exe`, and two Ctrl+C interruptions | Commands re-run correctly and recorded |
| Exit code not captured | `$p.ExitCode` was typed in a tab where `$p` was undefined | Exit confirmed instead by `HasExited` and `ExitTime` |
| Unrelated Wireshark stream | `tcp.stream eq 439` shows FakeNet-NG's default page from before the first run | Not used as sample evidence |
| Optional checks not performed | Existence of `xpupdate.exe`, a name-only task comparison and sample-specific Wireshark filters | Listed as limitations |
| Snapshot timing | `Lab02_PreExecution_ToolsReady` is time-stamped 9:04 PM (host), later than the recorded runs (20:49 to 20:57). No evidence compares the host and VM clocks, though the post-run snapshot timing suggests they agree within a few minutes | The snapshot is not relied on as a pre-execution restore point; the clean baseline is `Lab02_PreExecution_Baseline` |
| Baseline timing | The baseline snapshot precedes folder creation and extraction, but the time the archive reached the VM was not recorded | No claim is made about the archive download |

---

## Recommendations

**Improvements to the analysis process (drawn from the limitations above)**

1. Save the Process Monitor capture (`.pml`) to the evidence folder immediately after each run.
2. Execute one run per snapshot restore so changes can be attributed to a single execution.
3. Capture the process baseline to a file (`b_ps.txt`) along with the other baselines.
4. Enable Regshot directory scanning for the paths of interest, and record a host-versus-VM clock comparison at the start.
5. Apply sample-specific filters in Wireshark (destination IP, `download.php`, DNS for the Host name) and search the capture for DNS activity.
6. Check whether `C:\Windows\xpupdate.exe` exists and record its metadata and SHA-256; run a name-only scheduled-task comparison.

**Defensive use of the findings (derived from the observed indicators; not tested in a production environment)**

1. Search endpoint telemetry for the SHA-256 values and imphash listed above.
2. Look for new `HKCU\...\CurrentVersion\Run` values named `con` or `Windows update loader`, or values pointing at `C:\Windows\xpupdate.exe`.
3. Search proxy and network logs for HTTP requests to `/download.php` containing `advid=00000717`, and for traffic to `69.50.175[.]181`.

---

## Key Learning Outcomes

- Designing and proving an isolated dynamic-analysis environment before any execution.
- Establishing and maintaining evidence integrity with hashes, snapshots and separate working folders.
- Demonstrating packing from several independent angles, and understanding why whole-file entropy alone can mislead.
- Safely unpacking a sample with the packer's own workflow and keeping both versions traceable.
- Using simulated network services to capture communication attempts safely and correlating them with process IDs.
- Distinguishing observation from inference, assigning confidence levels, and mapping to MITRE ATT&CK only where evidence supports it.
- Recording errors, gaps and limitations openly instead of smoothing them over.

---

## Professional Value

This project demonstrates, with evidence, that the author can:

- **Run a malware analysis safely and methodically**, from isolation proof through restoration.
- **Combine static and dynamic analysis** to move from "this file looks packed" to "this is what it did".
- **Correlate network, process and registry evidence** to build a defensible narrative.
- **Produce usable indicators** (hashes, imphash, network indicators, registry values) with sources and timestamps.
- **Communicate with calibrated confidence**, naming limitations and unverified areas instead of overstating results.
- **Keep disciplined evidence records** that another analyst could follow and verify.

---

## Conclusion

`financials-xls.exe` is a UPX-packed 32-bit Windows GUI executable. Static analysis and a successful unpack give high confidence in the packing result. In three executions inside a Host-only VM with simulated services, the sample ran for about two seconds, displayed a fake spyware-infection alert and sent an HTTP GET to the hard-coded address `69.50.175[.]181:80`, requesting `/download.php` with a constant `advid` and varying `u` and `p` parameters. Two HKCU Run values appeared during the monitoring window: one pointing at the sample's own path and one pointing at `C:\Windows\xpupdate.exe`.

The most likely capability is a scareware or rogue-security-style program that contacts a remote server and sets up Run-key persistence. Confidence is **medium** overall: high for packing, the alert and the network requests, medium to medium-high for persistence, and **low** for what any downloaded payload might do, because the server was simulated. File activity, the full process tree and anti-analysis behaviour remain unverified and are documented as limitations.

---

The malware sample and its unpacked copy are intentionally **not** stored in this repository. Screenshots captured during the exercise are not published here; they are referenced by the technical report and the evidence log.

---

## Disclaimer

- This project was performed for educational purposes in an isolated, authorised lab environment on a course-provided sample.
- Do not execute malware outside an isolated analysis environment.
- Network indicators are defanged. Do not interact with the listed IP address or domain.
- Findings describe behaviour observed in one controlled environment with a simulated server and may not represent behaviour in the wild.
- Detection suggestions are derived from the observed indicators and were not validated in a production environment.

---

## References, Attribution and Acknowledgements

**Tools and frameworks referenced**

- Oracle VirtualBox and VBoxManage
- FLARE-VM
- UPX (Ultimate Packer for eXecutables)
- Detect It Easy (DIE)
- pestudio (Winitor)
- PE Detective
- Sysinternals Process Monitor, Process Explorer and Autoruns
- Regshot
- FakeNet-NG
- Wireshark
- MITRE ATT&CK

**Attribution**

- The sample, `financials-xls.exe`, was provided by the course for this exercise ("Course provided Malware Sample 2") and is not redistributed here.

**Acknowledgements**

- Course instructors for providing the controlled exercise and sample.
- The authors and maintainers of the open-source and free tools listed above.was used during this project to provide step-by-step guidance through the lab, to explain commands and concepts, and to help draft the technical report and this README. All commands were run, and all evidence was captured, by the author in the author's own lab environment. The content of this document is limited to the information and evidence contained in the project's report and evidence captures. The author reviewed the material and is responsible for its accuracy.
