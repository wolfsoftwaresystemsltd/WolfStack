# Think like a defender

Welcome to Level 3. This one's different from the others — it's not about a feature, it's about a **mindset**. Everything else you've learned makes your setup *work*. This course keeps it *yours*.

Here's the plain truth from the harden-the-server lesson, worth repeating: **the moment a server touches the internet, it's being scanned and attacked — constantly, automatically, forever.** Not because you're a target, but because everyone is. The bots never sleep. The good news: you don't have to be unbeatable. You just have to be **more trouble than the next server along** — and a handful of layers makes you exactly that.

## Defence in depth

Real security isn't one wall. It's **layers**, so that when one fails — and one eventually will — the next one catches it:

1. **Reduce the surface** — don't expose what you don't need (the firewall).
2. **Keep attackers out** — strong login, 2FA, lockouts, known-bad blocking.
3. **Catch what gets in** — malware and intrusion detection on the box itself.
4. **Don't hand them the keys** — no default passwords, patched software.
5. **See it early** — watch for the signs before it's a disaster.
6. **Recover cleanly** — a plan for when something *does* get through.

You've already built layers 1–2 in Getting Started (you locked your login and pushed a brute-force policy in the security lessons there). Level 3 finishes the set: detection, hygiene, early warning, and recovery.

## The attacker's playbook (so you can break it)

Almost every attack follows the same stages: **recon** (scan you) → **access** (break in) → **persistence** (hide and stay) → **damage** (steal, encrypt, mine crypto). Each layer above breaks a different stage. You don't need to stop all of them — **breaking any one stage stops the attack.**

> **The mindset that matters most: assume you'll be breached, and build so it doesn't matter.** Back up so ransomware is an annoyance, not a catastrophe. Segment so one cracked container isn't the whole fleet. Monitor so you find out in minutes, not months. Hope is not a security strategy; layers are.

## ✓ What you just learned

- Security is **layers** (defence in depth), not a single wall — when one fails, the next catches it.
- Attacks follow **recon → access → persistence → damage**; breaking **any one stage** stops them.
- Getting Started gave you the first layers (login, lockout). Level 3 adds **detection, hygiene, early warning, and recovery**.
- **Assume breach** and build so it doesn't ruin your day.

## Ready?

Next door: the **firewall** — the single biggest reduction in attack surface you can make, and it's right here in WolfStack.
