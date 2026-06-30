# When something gets in

Someday, despite every layer, something will get through — or you'll get the alert that makes your stomach drop. This is the lesson nobody wants and everybody needs: **what to actually do.** Panicking is the only real mistake. You have a plan now.

## Stay calm and work the steps

The professional order is **isolate → assess → eradicate → recover → learn.** Don't skip to "wipe everything" and don't pretend it's nothing. Work the steps.

## 1. Isolate

Stop the bleeding before you investigate. Cut the compromised machine off so an attacker can't spread or exfiltrate:

- Tighten its **firewall** (WolfRouter) to cut external traffic, or pull it from the network.
- WolfStack's **Fleet Security** tools let you **quarantine** and lock things down fast.
- Hit **Logout everyone, everywhere** and **rotate root passwords fleet-wide** (from the harden lesson) if credentials might be compromised — *save the new passwords immediately.*

A contained incident on one box is survivable. An attacker free to roam your whole fleet is not.

## 2. Assess — what did they touch?

Figure out the blast radius before you act further:

- What raised the alert? A **Compromise** flag, a strange login, a process in **`/tmp`/`/dev/shm`**?
- What did that process do, what's it connected to, what user ran it?
- Which machines can the affected one reach? (This is *why* segmentation and WolfNet matter.)

## 3. Eradicate and recover — trust your backups

Here's where Getting Started pays off enormously. **You have backups.** That changes everything:

- The only way to *truly* trust a compromised machine again is to **rebuild it** and **restore data from a known-good backup** taken *before* the breach.
- Don't restore a backup that's newer than the compromise — you'll just restore the attacker with it.
- This is exactly why you take backups regularly and keep history: so you have a clean point to fall back to.

Rotate every credential the machine could have seen. Assume anything it touched is burned.

## 4. Reporting — your call, your finger on the button

If an attack came from a specific source, WolfStack can help you compose an **abuse report** to the offending network. One firm rule: **these are never sent automatically.** WolfStack drafts it; **you** review every word and **you** press Send. Outbound notifications to third parties are always a deliberate human decision — never a button the software pushes for you.

## 5. Learn

Afterwards, ask the honest question: **how did they get in, and which layer would have stopped it?** Then add that layer. Every incident is a free lesson in where your defences were thin.

> **Backups are your reset button — guard them like one.** Ransomware's entire business model is making your data unrecoverable. Off-box backups, kept long enough to predate a slow breach, turn "we're ruined" into "we restore from Tuesday." If you take one thing from this whole course: a tested, off-box backup is the most powerful security control you own.

## ✓ What you just learned

- Incident order: **isolate → assess → eradicate → recover → learn** — calm beats clever.
- **Isolate** with the firewall/quarantine; **rotate creds** and **logout everyone** if login may be compromised.
- The only real recovery is **rebuild + restore from a known-good backup** taken *before* the breach.
- **Abuse reports are manual** — WolfStack drafts, **you** press Send.
- Every incident teaches you which **layer** to add next.

## Try it

Don't wait for a real incident to think about this. Right now, answer: *if my main server were compromised tonight, which backup would I restore, and is it off-box?* If you can't answer confidently, that's your most important security task this week.
