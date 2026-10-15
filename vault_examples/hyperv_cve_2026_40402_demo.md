# Vault Entry Demo — Hyper-V CVE-2026-40402 (Singleton Severity Outlier)

> Second §0 prototype. The ksmbd case was **cluster + density** (easy mode). This case is **singleton CVSS 9.3** — no density, lateral expansion has to work cross-surface rather than within a cluster. A test of whether the spec is general.
>
> Production raw material: MSRC fetcher output (1865 CVEs / 3 bulletins / last 3 months), Hyper-V product cluster (4 CVEs: 40402=9.3, 26156=7.8, 32149=7.3, 25170=7.0), Windows Kernel adjacent cluster (17 CVEs), Exploitation Detected list (5 entries, no Hyper-V).

---

```
title: "CVE-2026-40402: Hyper-V [TODO subsystem] — [TODO bug class]"
author: Utku
date: 2026
tags: [CVE-2026-40402, Hyper-V, Windows, hypervisor, guest-to-host, VM-escape, CVSS-9.3, methodology-trace]
license: CC BY 4.0
```

> **Author's Note:** [TODO — after the MSRC detail is fetched]

---

## Abstract

[TODO]

---

## §0 Discovery Trace

The surface was entered through a severity-outlier observation in the most recent MSRC bulletin window. Across 1865 vulnerabilities in three months, Hyper-V was represented by four CVEs — a small cluster, statistically uninteresting on its own. The signal was distributional: three of the four sat between CVSS 7.0 and 7.8, while one — CVE-2026-40402 — stood alone at 9.3. A single ≥9.0 case in a host-kernel virtualization product is a different shape of signal than a density cluster. It does not say "an invariant broke for many callers"; it says "one path crosses a trust boundary that the others don't." For a hypervisor surface, the trust boundary that explains a 9.3 is almost always guest-to-host. The entry was the gap between the outlier and its siblings, not the cluster itself.

Lateral expansion had to look outside the Hyper-V cluster, since four cases cannot support intra-cluster semantic correlation. Two adjacent surfaces were in the same window: 17 Windows Kernel CVEs (an active-pressure surface, far above its baseline), and a parallel hypervisor surface on the Linux side (KVM CVEs in NVD over the same period). The relevant bridge was the Windows Kernel pressure — host-kernel attack surface is the *target* of any successful guest-to-host escape, so concurrent pressure on the kernel surface raises the value of any working VM exit. The hypothesis that crystallized: this is not a hypervisor-internal bug class (those tend to score 7-8 — process isolation, denial of service); this is a boundary-crossing class whose post-exploitation chains directly into the actively-pressured kernel surface.

Elimination narrowed from there. Three negation steps. *First:* this is not in the exploitation-detected set (five entries that window — Exchange, Defender ×2, Windows Shell, SharePoint; Hyper-V absent). That places the case in the **pre-exploit window** — researcher value is highest before public weaponization, drops afterward. *Second:* the surface is not "Hyper-V management plane" — the management plane CVEs in this window scored 7.x with privilege-bounded impact; a 9.3 with VM-escape implication has to sit in the hypervisor's data plane, where guest-controlled inputs reach host-kernel code. *Third:* the surface is not a known-hardened path — Hyper-V has years of dedicated mitigation work on its vmbus/vmswitch/RDP-virt paths, and 9.3 outliers tend not to land where the mitigation density is already high; the bug surface is more likely a recently-introduced or under-attended component. What remains is a narrow band: data-plane, recently-attended, guest-input-reachable, host-kernel-executing. The specific component and bug class is the subject of §1-§3.

---

## §1 Hyper-V Architecture and the Guest/Host Trust Boundary

[TODO]

## §2-§N [Bug analysis, exploit chain, mitigations bypassed, post-escape pivoting]

[TODO]

## §N+1 Portfolio Relationships

- **EPT Hypervisor Hook Writeup** (`../EPT-Hypervisor-Hook-Writeup`): Both operate at the same trust boundary. EPT hook discusses how the hypervisor *enforces* guest isolation through extended page tables; this CVE discusses what happens when a data-plane path lets guest input cross the very boundary EPT is supposed to seal. The two are dual surfaces of one problem: §0's "pre-exploit window" framing is meaningful precisely because EPT-class mitigations are *already in place* — the bug must reach a code path that those mitigations don't cover.

- **PatchGuard Hypervisor Bypass Writeup** (`../PatchGuard-Hypervisor-Bypass-Writeup`): Same surface-class (host-kernel post-escape pivoting). The Hyper-V escape lands the attacker on the Windows host kernel; PatchGuard is what immediately challenges any persistent foothold gained there. The §0 lateral-expansion observation (17 Windows Kernel CVEs in same window = active pressure) is the same kernel surface PatchGuard sits on top of.

- **VMExit API Unhook Writeup** (`../VMExit-API-Unhook-Writeup`): Both touch the VMExit path — VMExit-Unhook from the detection-evasion angle, this from the exploitation angle. Cross-link makes the §0 elimination step ("not management plane, is data plane") portfolio-coherent: the data plane *is* the VMExit-handler surface.

- [TODO additional cross-link]

---

## Self-Quality-Gate

> "If we deleted this §0, what would be lost from the writeup?"

What would be lost if deleted: **reading this CVE not as a single isolated bug but as a position in a space**. §1-N still explain the bug, but without §0 the reader infers "a CVE list was scanned, the highest CVSS was picked" — a counting signal. With §0 the reader sees: the outlier *says something*, adjacent surface pressure *says something*, the pre-exploit window *says something*. The sum of these is this signal: this person isn't reading CVSS scores, they're reading **opportunity topology**. Signal (3).

§0 is successful. The format holds in the singleton case too.

---

## Format Trial — Observations

### 1. The entry signal was generalized
In the ksmbd case the entry signal was **density** (3 CVEs / same CWE / narrow window). In this case it's a **severity outlier** (1 CVE / same product family / distributional gap). The spec didn't define the entry signal as a single signal class — it said "the first signal, express it with numbers, a preliminary answer to the why-here question." That turned out right. The spec shouldn't change.

### 2. Lateral expansion had to work **cross-surface**
In ksmbd, lateral expansion was a semantic cross-CWE bridge **within the cluster** (CWE-416 ↔ CWE-667). Here there's no cluster — lateral expansion was done via an **adjacent surface** (Windows Kernel pressure) and a **cross-vendor mirror** (the KVM ecosystem). The spec had listed three options: "semantic correlation, cross-CWE bridge, adjacent-surface connection" — two of them on the list hold (adjacent surface, and cross-vendor as implicitly adjacent). The spec is sufficient, but a small clarification could be made: in paragraph 2 the principle "if there's no cluster, go to the adjacent surface" could be made explicit. Right now it's implicit.

### 3. Elimination was **multi-step**, in ksmbd it was **single-step**
In ksmbd, elimination was built on a single negation (the per-handle ownership pattern was the one eliminated). Here three negations were needed (not exploited, not management plane, not hardened path). The spec didn't limit the step count on the elimination paragraph — it's flexible. Good news. But in the Hyper-V case the three negations made §0 longer (paragraph 3 is longer than the other two). A one-or-two-sentence tonal note could be added to the spec: "the elimination shouldn't be longer than paragraph 2 — if needed, move it into paragraph 2." Right now the spec is silent.

### 4. The forbidden-name list is sufficient again
Across the entire §0, no confidential term leaked. "MSRC", "NVD" — these are public sources, not forbidden. "Severity outlier", "distributional gap", "adjacent surface pressure", "pre-exploit window" — all principle-level. Name discipline is solid.

### 5. Cross-references in §N+1 were bridged with §0's structural categories
Per the spec: the structural reading used in §0 is connected to another writeup in §N+1 via at least one cross-link. In this case there are three cross-links (EPT-Hook, PatchGuard, VMExit-Unhook), each of which connected a reading point from §0 (mitigation density, post-escape kernel surface, VMExit-handler surface) to a concrete writeup. The spec worked.

---

## Conclusion About the Spec

The two tests (cluster + singleton, density + outlier, intra-correlation + cross-surface, single-step + multi-step elimination) showed that the format is **shape-independent**. Two small improvement suggestions:

- **Spec change suggestion 1:** The sentence "Lateral expansion: if the cluster is insufficient, it opens to the adjacent surface and cross-vendor mirror" could be added explicitly
- **Spec change suggestion 2:** A tonal note "Elimination should not be longer than paragraph 2; if needed, a step is handed off to paragraph 2" could be added

These two changes are small; the spec overall is solid. The next step A (a full writeup for a real CVE) can now be done safely.
