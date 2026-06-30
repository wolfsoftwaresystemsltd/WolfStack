# Control what's reachable (the firewall)

In Getting Started you used **Fleet Security → Internet-exposed services** to *find* what's open. This lesson is the next step: actually **controlling** it. The single most effective security move there is — close doors you don't need. An attacker can't break in through a door that isn't there.

WolfStack's firewall lives in **WolfRouter**.

## Open WolfRouter

In the sidebar, open **WolfRouter** (you'll find it on a server's view, and there's a cluster-wide WolfRouter for managing rules across every node at once).

WolfRouter is WolfStack's networking brain — and its **Firewall** is where you decide what traffic is allowed in, out, and between your machines.

## The one idea that matters: default-deny

There are two ways to run a firewall:

- **Default-allow** — everything's open; you block the bad stuff. You will always miss something.
- **Default-deny** — everything's closed; you open *only* what you actually need. Nothing slips through because nothing's open by default.

**Default-deny wins, every time.** It's the difference between "I hope I blocked everything dangerous" and "only the three things I chose can get in."

## Build a rule

A firewall rule is just: *allow [this traffic] from [here] to [there].* In WolfRouter's Firewall you create rules that spell out exactly what's permitted — for example, "allow web traffic (80/443) from anywhere to my web server," and nothing else inbound.

Work from a short allow-list:

- Your management UI (8553) — ideally only from **your** admin IP.
- The actual service you're publishing (e.g. 443 for a website).
- That's usually it. Everything else stays shut.

> **The golden rule of firewalls: add your own access first, then lock the rest.** Exactly like the Trusted-IPs warning from the harden lesson — the classic disaster is tightening a firewall and sealing *yourself* out. Confirm your management access is allowed, **then** close everything else. If you can, keep a second way in (console access) while you test.

## Pair it with WolfNet

Remember WolfNet from Level 2? The two work beautifully together: put server-to-server traffic on the **private WolfNet mesh** and you can keep those ports completely closed to the public internet. The database your app needs never has to be exposed at all.

## ✓ What you just learned

- **WolfRouter → Firewall** is where you control what traffic is allowed.
- Aim for **default-deny**: open only the few things you genuinely need.
- **Allow your own admin access first**, then close everything else — don't lock yourself out.
- Combine with **WolfNet** to keep internal services off the public internet entirely.

## Try it

Open WolfRouter and just *read* your current rules and exposed services. Knowing exactly what's reachable — and being able to say why each open port is open — is itself a big security win.
