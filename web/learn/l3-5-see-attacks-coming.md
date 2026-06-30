# See attacks coming

Detection is only half the job. The other half is **noticing** — because an alert nobody reads is the same as no alert at all. The difference between a minor incident and a disaster is almost always *how fast you found out.* Months of an attacker living in your system is a catastrophe; ten minutes is an inconvenience.

WolfStack gives you three places to look, each earlier than the last.

## 1. The Issues page — what's wrong now

In the sidebar, **Issues** is WolfStack's list of things it thinks you should look at right now — including security events. Make checking it a habit. A blocked-intruder note or a **Compromise** alert (remember `/tmp` and `/dev/shm`?) shows up here.

## 2. The Predictive Inbox — what's about to go wrong

Also in the sidebar, the **Predictive Inbox** is the early-warning system: it surfaces problems *before* they become incidents — things trending the wrong way, drifting out of date, starting to look off. For security, "before" is everything. This is where you catch the slow build-up rather than the explosion.

## 3. Alerts on your phone — when you're not looking

You set up alerts in Getting Started. For security, make sure the ones that matter actually **reach you** — a compromise alert is worthless sitting in a dashboard you're not looking at. Route the important ones to your phone, email, or chat so a 3am intrusion wakes *something* up.

## What to actually watch for

You don't need to read every log line. Watch for the handful of things that mean *something changed*:

- A login from a place or time that isn't you.
- An IP getting blocked repeatedly — someone's trying hard.
- A **Compromise** alert — treat as urgent.
- A service suddenly exposed that wasn't before.
- Resource use spiking with no reason (crypto-miners are greedy).

> **Tune the noise, or you'll learn to ignore the signal.** The fastest way to miss a real attack is to drown in alerts you've stopped reading. Send yourself the *important* ones loudly, let the routine ones sit quietly in the dashboard, and review the quiet ones on a schedule. Alert fatigue has cost more people their servers than any zero-day.

## ✓ What you just learned

- **Issues** = what's wrong now (including security events); make checking it a habit.
- **Predictive Inbox** = early warnings *before* something becomes an incident.
- Route the **important security alerts to your phone** so you find out in minutes, not months.
- Watch for *change* — odd logins, repeat-blocked IPs, Compromise alerts, new exposure, unexplained load.
- **Tune alerts** so the signal doesn't drown in noise.

## Try it

Open the **Predictive Inbox** and the **Issues** page and read what's there today. Knowing what "normal" looks like is exactly what lets you spot "wrong" the instant it appears.
