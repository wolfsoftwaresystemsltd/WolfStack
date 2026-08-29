# Security Policy

## Reporting a vulnerability

**Please report security issues privately — not as a public GitHub issue.**

Use GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/wolfsoftwaresystemsltd/WolfStack/security)
2. Click **Report a vulnerability**

> **Note for reporters:** the `/security/advisories/new` URL is the
> *maintainer* path for drafting an advisory and will 404 for anyone
> without write access to this repository. That is expected and does
> **not** mean private reporting is disabled — external reporters must
> use the **Report a vulnerability** button on the Security tab above.

If that is unavailable to you for any reason, email **paul@wolf.uk.com**
with `SECURITY` in the subject line.

## What to include

- Affected version or commit (`wolfstack --version`, or the release tag)
- What an attacker can do, and what access they need to start
- Reproduction steps — a `curl` invocation or short script is ideal
- Any logs or output that show the impact

If you have a working proof of concept, please exercise it only against
systems you own or are authorised to test.

## What to expect

- **Acknowledgement within 72 hours.**
- An assessment, and where we agree it is a vulnerability, a fix
  timeline. Critical issues are prioritised over all other work.
- Credit in the release notes and in the published advisory, under
  whatever name or handle you prefer — tell us which. Say so if you
  would rather not be credited.
- A CVE requested via GitHub's advisory process for issues that warrant
  one. You will be listed as the reporter.

We will keep you updated as the fix progresses, and we would appreciate
it if you hold public disclosure until a fixed release is available.
We are not going to threaten anyone who reports a genuine issue in good
faith.

## Supported versions

Only the latest release receives security fixes. WolfStack ships
frequently; upgrade to the current release before reporting, and check
that the issue still reproduces there.

| Version | Supported |
|---|---|
| Latest release | ✅ |
| Anything older | ❌ — upgrade first |

## Hardening notes

Some deployment choices materially change your exposure:

- **Rotate the cluster secret.** Settings → Security → Rotate cluster
  secret. A node that has never rotated is running with a value that is
  a constant in this repository's source. WolfStack auto-generates a
  per-install secret on fresh installs and refuses the built-in default
  from any address that is not an already-recorded cluster peer, but
  rotating removes the question entirely.
- **Do not expose the management port (8553) to the internet.** Put it
  behind a VPN, a WireGuard tunnel, or an IP allowlist. WolfStack runs
  as root by design (it reads `/etc/shadow` for authentication) and
  manages containers, VMs and storage — treat the port accordingly.
- **Keep `/etc/wolfstack` at mode 0700 and owned by root.** WolfStack
  enforces this at startup, but a restore-from-backup can loosen it.
- Set `WOLFSTACK_REJECT_DEFAULT_SECRET=1` to refuse the built-in default
  outright, including between recorded peers, once your whole cluster
  has rotated.
- **The cluster secret is a cluster-wide credential — guard it like root.**
  Every node holds the same symmetric secret, so a peer that has it can
  do what any peer can do. Since 25.9.3 (extended in the release after
  25.21.2 to the whole exec/console/file surface) a *bare* secret cannot
  open a shell or touch files: those endpoints demand an operator
  attribution that only a forwarding node adds. That is containment for
  accidents and for the published default, not cryptographic proof of
  identity — a secret-holder who forges the attribution headers is still
  a peer. Treat a leaked cluster secret as a full-cluster compromise:
  rotate it immediately from a trusted node.
- **Require node signatures once every node runs 25.22 or later.** Each
  node now holds its own Ed25519 key (`/etc/wolfstack/node-key`) and
  signs every inter-node request; peers pin the public key from the
  node's own reports. By default nothing is enforced — an upgrade changes
  no behaviour. Settings → Security → *Require node signatures* (once it
  reports every peer has a key) makes a cluster secret worthless on its
  own: a request must be signed by a pinned node, bound to the receiving
  node, and only nodes left as *managers* in their node settings may
  forward operator actions. `WOLFSTACK_NODE_SIGNATURES=off` in the
  service environment turns it back off over SSH if you lock yourself
  out. What this still cannot do: a fully compromised *manager* node can
  act as its operators — no peer-symmetric cluster can prevent that
  without an external trust anchor.
