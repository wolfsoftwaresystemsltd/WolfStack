# The defender's checklist

You've gone from "the internet is scary" to having a real, layered defence and a plan for when it's tested. That's a genuine skill — most people running servers never get here. Let's pull it together into something you can actually use: a checklist you can run any time you want to know *am I in good shape?*

## The layered-defence checklist

Run down this list for each setup. Every "yes" is a layer an attacker has to beat:

**Reduce the surface**
- [ ] Firewall is **default-deny** — only the ports I deliberately chose are open (WolfRouter).
- [ ] Internal services are on **WolfNet**, not exposed to the internet.
- [ ] **Internet-exposed services** has nothing red I didn't intend.

**Keep them out**
- [ ] Strong, unique passwords; **2FA or passkeys** on every admin.
- [ ] **Brute-force lockout** policy pushed — with **my own IP trusted** first.
- [ ] **NMAP Protection** + **Threat Intel** on.

**Catch what gets in**
- [ ] **On-access antivirus** on.
- [ ] **Scan detector** on; I read **Compromise** alerts and know `/tmp`·`/dev/shm` means trouble.

**Don't hand over the keys**
- [ ] **Secret-audit** clean; not on the **default cluster secret**.
- [ ] Default app passwords all changed; software **patched**.

**See it early**
- [ ] I check **Issues** and the **Predictive Inbox**; important alerts reach my **phone**.

**Recover cleanly**
- [ ] **Off-box backups**, taken regularly, kept long enough — and I know which I'd restore.

If most of those are ticked, you're ahead of the overwhelming majority of servers on the internet. You don't need perfection — you need **layers**, and you have them.

## Security is a practice, not a state

The one thing to internalise: **you're never "done" being secure.** New holes appear, software ages, you add machines, attackers adapt. Security isn't a box you tick once; it's a few small habits you keep:

- Patch and update — a little, often.
- Glance at Issues and the Predictive Inbox.
- Let a backup run, and occasionally *test a restore* (an untested backup is a hope, not a plan).
- Open a new door only with a real need (you've heard that one before — it's a security control too).

> **The bar isn't perfect, it's resilient.** You will not stop every attack, and you don't have to. Build so that when one gets through, it hits a wall, you find out fast, and you recover from a clean backup. That's not paranoia — it's just being a good operator. And that's exactly what you've become.

## ✓ What you just learned

- A practical **layered-defence checklist** you can run on any setup, any time.
- Every layer you tick is one more thing an attacker has to beat — **you don't need perfection, you need layers**.
- Security is an ongoing **practice** (patch, watch, test restores, add doors by need), not a one-time setting.
- Aim for **resilient**, not perfect: get in their way, notice fast, recover clean.

## You did it

Three courses. From "what is a server" to a layered, defended, recoverable operation that you understand top to bottom. Go run it like the operator you are — and sleep well, because you built it to take a hit and keep going. 🐺
