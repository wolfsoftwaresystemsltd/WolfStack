# WolfStack — Licensing & Sponsorship

Plain-English summary. The authoritative legal terms are in [LICENSE](LICENSE);
current plans and prices are at <https://wolfstack.org/enterprise.php>. If
anything here disagrees with the LICENSE file, the LICENSE file wins.

## The model in one paragraph

WolfStack is **source-available, not open source.** It is **free** for
personal, homelab, education, research, and non-profit use under the
[PolyForm Noncommercial Licence 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0).
**Commercial use requires a paid subscription.** Separately, anyone can
**sponsor** development on GitHub or Patreon — that's an optional donation,
not a licence.

## Sponsoring vs licensing — they are different things

These get confused constantly, so to be explicit:

| | **Sponsorship** (GitHub / Patreon) | **Commercial licence** (subscription) |
|---|---|---|
| What it is | A voluntary donation that funds development | A paid right to use WolfStack commercially |
| Who it's for | Homelab / personal users who want to chip in | Any business or revenue-generating use |
| Grants commercial-use rights? | **No** | **Yes** |
| Unlocks paid features? | No | Yes (see below) |
| In-app perks | No support nag, early-access (beta) builds, private roadmap, Discord support | All of that, plus the licensed features |
| Cancel anytime? | Yes | Subscription term applies |

> Sponsoring **does not** make commercial use legal. If you run WolfStack at or
> for a business, you need a commercial licence even if you also sponsor.

## What's free vs what needs a licence

Almost everything is free for everyone. A small set of **business** features
are gated behind a commercial licence:

| Feature | Free (noncommercial) | Licence required |
|---|---|---|
| Docker / LXC / VM management, clustering, networking, storage, backups, status pages, monitoring, the App Store, WolfNet, WolfRouter… | ✅ | |
| API tokens | | Homelab+ |
| SSO | | Team+ |
| Plugins | | MSP+ |
| Multi-tenancy | | MSP+ |
| White-label / managed-hosting (WolfHost, WolfCustom) | | MSP+ |

> A licence file is deployed to `/etc/wolfstack/license.key`; the binary
> validates its signature locally and never phones home for verification.

## Commercial licence tiers

Buy at <https://wolfstack.org/enterprise.php>. Feature inclusions (from the
licence the binary validates):

| Tier | Adds | Hosts |
|---|---|---|
| **Homelab** | Commercial-use right + API tokens | capped |
| **Team** | + SSO | capped |
| **MSP** | + plugins, multi-tenancy, white-label / managed hosting | capped |
| **Enterprise** | Everything | unlimited / quoted |

For bespoke SLAs, air-gapped deployment, compliance collateral, custom
development, or large-fleet pricing, contact **sales@wolf.uk.com**.

## Sponsorship tiers

Sponsoring is a donation. **Every paying sponsor — at any amount — gets the
same in-app perks:** the support nag stops, and the **beta update channel**
unlocks. Higher tiers are about recognition and how much you're helping, not
about unlocking different features. (Beta builds used to require a higher
Patreon tier while a free self-attest also granted them — that inconsistency
is gone: beta = any supporter.)

Recommended levels, kept **the same across GitHub Sponsors and Patreon** so
there's one coherent ladder:

| Monthly | Name | What you get |
|---|---|---|
| **$3** | Supporter | Funds development. No support nag, early-access beta builds, private roadmap, Discord supporter role. |
| **$25** | Backer | Everything above + your name on the supporters page / in-app credits. |
| **$95** | Platinum | Everything above + your logo + link on the website, priority issue triage. |

> **Action required (one-time, on GitHub):** GitHub Sponsors tiers are
> configured in the GitHub Sponsors dashboard, not in this repo. Create the
> three tiers above at
> <https://github.com/sponsors/wolfsoftwaresystemsltd/dashboard> so they line
> up with the Patreon tiers (`$3` Basic, `$25` Advanced, `$95` Platinum) that
> `src/patreon.rs` already recognises.

### How in-app supporter status is determined

The binary considers you a supporter — removing the nag and unlocking beta — if
**any** of these is true:

1. A valid commercial **licence** is present (`/etc/wolfstack/license.key`).
2. A linked **Patreon** account with a paying pledge ($3+/mo). Verified via the
   Patreon API (link it in Settings).
3. The operator has ticked **"I'm a GitHub Sponsor"** (honour system — GitHub's
   API doesn't let us enumerate sponsors, so we trust the tick).

## Prior releases

Releases up to and including **v22.9.x** were published under the MIT Licence
and remain available under it in perpetuity. **v22.10.0 and later** are under
the dual licence described above.

## Trademarks

WolfStack™, WolfRouter™, WolfAgents™, WolfNet™, WolfFlow™, WolfRun™, WolfUSB™
and WolfDisk™ are trademarks of Wolf Software Systems Ltd. The licence covers
the source code, not the trademarks.
