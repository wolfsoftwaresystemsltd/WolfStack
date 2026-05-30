# Harden the server

Here's an uncomfortable truth worth saying plainly: **the moment a server is reachable from the internet, it is being scanned and brute-forced — within minutes, constantly, forever.** This isn't paranoia, it's just the weather. People lose whole servers to it. The good news is WolfStack gives you the tools to shut almost all of it down from one screen.

The previous lesson locked your *login*. This one hardens the *server*.

## Your security command centre

Open the **Apps & Tools** drawer (the grid icon at the top of the sidebar) and click **Fleet Security**. This one screen covers every node in your cluster.

## 1. Stop brute-force attacks (the big one)

Find the **Brute-force lockout policy** card. This automatically blocks any IP that fails to log in too many times — across the WolfStack UI, SSH, *and* the Proxmox UI. Set:

- **Failures before block** — how many bad attempts are allowed (default **10**).
- **Detection window (sec)** — the time those failures are counted over (default **300**).
- **Lockout (sec)** — how long a blocked IP stays banned (default **172800** = 48 hours).
- **Trusted IPs / CIDRs** — **⚠️ the most important field. Put your own admin IP address here BEFORE you save.** These IPs are never locked out, on any node. Get this wrong and you can ban yourself from your own server.

Then click **Push policy to every node**. One policy, your whole fleet, done.

> If you don't have a static IP at home, you can still use this — just be ready to unblock yourself (next section) if your address changes and you fat-finger a password.

## 2. See and clear blocked IPs

The **Blocked IPs across the fleet** card lists every IP currently banned on any node, what it was doing, and lets you **Unblock** — handy if you ever lock yourself out.

## 3. Close doors you didn't mean to leave open

The **Internet-exposed services** card lists every service reachable from the internet, colour-coded:

- 🔴 **Red** — high-risk (databases, admin panels, file shares). If something red is here that you didn't *deliberately* expose, that's a hole to close.
- 🟡 **Yellow** — exposes credentials (FTP, Telnet, etc.).
- 🟢 **Green** — normal public services (a website on 80/443).

This is the single best "am I exposed?" check you can do. Anything red and unexpected → firewall it or stop the service.

## 4. Block the scanners before they start

Attacks begin with a **port scan** (reconnaissance). WolfStack can block scanners automatically: go to a node's **Settings → Security** and turn on **NMAP Protection**. It detects scan patterns and bans the source before they find a way in. Turn it on.

Nearby you'll also find **Threat Intel** — a feed of known-bad IPs that gets blocked automatically. Keep it enabled.

## 5. The "we've been breached" panic kit

If you ever think a node is compromised, Fleet Security has two emergency buttons:

- **Rotate root passwords fleet-wide** — generates a fresh random root password on every node and kills active root SSH sessions. *(It will end your own SSH session — save the returned passwords immediately.)*
- **Logout everyone, everywhere** — kills every dashboard session.

## ✓ What you just learned

- The internet attacks every exposed server constantly — **Fleet Security** is where you fight back.
- Push a **brute-force lockout policy** — and **add your own IP to Trusted IPs first** so you don't ban yourself.
- Use **Internet-exposed services** (red/yellow/green) to find and close unintended holes.
- Turn on **NMAP Protection** + **Threat Intel** to block scanners and known-bad IPs automatically.
- Know the emergency buttons (**rotate root passwords**, **logout everyone**) before you need them.
