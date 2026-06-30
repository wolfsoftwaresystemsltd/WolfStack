# No default secrets, no stale software

The fanciest firewall in the world won't save you if you left the key under the mat. A huge share of real break-ins aren't clever hacks at all — they're **default passwords nobody changed** and **known holes in software nobody updated**. This lesson closes both, and it's the least glamorous, highest-value security work you'll ever do.

## 1. Hunt down default secrets

A "default secret" is any password, key, or token that shipped with a default value — the kind every attacker already knows. WolfStack actively checks for these.

- Watch the **dashboard** for a **secret-audit** warning banner. It flags committed-default secrets it can find on your nodes.
- The big one it checks: the **default cluster secret**. If your cluster is still using the built-in default, *anyone who knows it can talk to your cluster as a trusted node.* Rotate it.

If the audit flags something, fix it. A default credential is an open door with a welcome mat.

## 2. Change every default password

Beyond WolfStack's own secrets, every app you install can ship with defaults — database root passwords, admin panels with `admin/admin`, sample API keys. When you install something, your first job is: **find its default credentials and change them.** Bots scan for default logins on every common app, all day long.

## 3. Keep software updated

Most "hacks" exploit a hole that was **already fixed** — on machines that never installed the fix. Patching isn't optional housekeeping; it's front-line defence.

- Keep WolfStack itself current — updates carry the security fixes.
- Keep your containers and VMs updated. An old image is an old set of known holes.
- Remember the **Predictive Inbox** (next lesson) surfaces things drifting out of date before they bite.

> **Supply chain — trust, but pin.** The software you didn't write is still your responsibility. Prefer official images, pin versions so an update can't silently swap in something nasty, and be sceptical of random one-line `curl | bash` installers from places you don't know. Most "I got hacked" stories start with software the operator never really vetted.

## ✓ What you just learned

- WolfStack's **secret-audit** banner flags committed-default secrets — especially the **default cluster secret**. Rotate anything it finds.
- **Change every default password** on the apps you install — bots scan for them constantly.
- **Patch everything** (WolfStack, containers, VMs) — most attacks exploit already-fixed holes.
- Treat your **software supply chain** with care: official images, pinned versions, vetted installers.

## Try it

Glance at your dashboard for a secret-audit warning, and confirm your cluster isn't on the default secret. Two minutes; it closes one of the most common doors there is.
