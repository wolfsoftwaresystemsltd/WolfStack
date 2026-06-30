# Catch malware and intruders on the box

Layers one and two keep most attackers out. This layer assumes one got through anyway — and catches them **on the machine itself**. This is where a lot of setups have a blind spot: they lock the front door and never check whether someone's already inside.

WolfStack's on-box detection lives mostly in **Settings → Security** (on each node) and **Fleet Security** (across the fleet).

## 1. On-access antivirus

In **Settings → Security**, turn on **Antivirus (ClamAV)** with **on-access** scanning. On-access means files are checked **the moment they're written or run**, not just on a nightly sweep — so a malicious upload or download is caught as it lands, not hours later. There's a fleet-wide antivirus view in **Fleet Security** too, so you can see coverage across every node.

## 2. The scan detector

Also in **Settings → Security**, the **scan detector** (and **NMAP Protection** from the harden lesson) watch for the reconnaissance that comes *before* an attack — someone probing your ports looking for a way in — and block the source automatically. Keep these on.

## 3. The signal that means "you're already compromised"

Here's a piece of real defender knowledge worth memorising. **A program running from `/tmp` or `/dev/shm` is one of the strongest signs of a break-in there is.** Those are scratch directories — legitimate software almost never *runs* from them. Attackers love them because they're writable and often overlooked. Crypto-miners (like `xmrig`), fileless malware, and freshly-dropped reverse shells stage there constantly.

WolfStack's scanner watches for exactly this and raises it as a **Compromise** alert. If you ever see one:

- **Don't ignore it.** This is the high-priority kind.
- Note the **process, its parent, and the user** running it.
- Treat the machine as suspect until you've explained it (a few dev tools legitimately use `/tmp` briefly — but verify, don't assume).

That single check — "is anything running from `/tmp` or `/dev/shm`?" — catches a huge share of real-world server compromises. WolfStack does it for you automatically.

> **Detection only helps if you look.** All the scanning in the world is useless if the alert lands in an inbox no one reads. The next lessons are about making sure you actually *see* these — but turn the detection on first, here, today.

## ✓ What you just learned

- **Settings → Security** is where you enable on-box detection per node; **Fleet Security** shows it fleet-wide.
- Turn on **on-access Antivirus (ClamAV)** so threats are caught **as files land**, not nightly.
- Keep the **scan detector** + **NMAP Protection** on to block recon before the attack.
- A process running from **`/tmp` or `/dev/shm`** is a classic compromise signal — WolfStack flags it as a **Compromise** alert; never ignore one.

## Try it

Open **Settings → Security** on your main server and confirm on-access antivirus and the scan detector are **on**. Two toggles, a genuinely big jump in how much you'd notice an intrusion.
