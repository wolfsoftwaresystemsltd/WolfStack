# Get alerts on your phone

The Issues page is great when you remember to look. Alerts are for when you *don't* — they reach out to you. Set this up once and WolfStack will message you when a server goes offline or runs hot, instead of you finding out the hard way.

## Open alert settings

1. Click **Settings** (the cog, bottom-left).
2. Open the **Alerts** tab.
3. In the left-hand list, click **Notifications**.

## Pick how you want to be reached

WolfStack can send alerts to the places you already check. Fill in whichever you use — you don't need all of them:

- **Discord Webhook URL** — in Discord: *Server Settings → Integrations → Webhooks*, create one, paste the URL.
- **Slack Webhook URL** — from *api.slack.com/apps → Incoming Webhooks*.
- **Telegram** — paste a **Telegram Bot Token** (from `@BotFather`) and your **Telegram Chat ID** (from `@userinfobot`).
- **ntfy** — the easiest route to real push notifications on your phone: install the free [ntfy](https://ntfy.sh/) app (iOS/Android), pick a long random **topic** name, enter the same topic here. No account needed on the public ntfy.sh server — but the topic name is effectively a password, so make it unguessable. Self-hosted ntfy servers work too (set the server URL and, if needed, an access token).

> Most people pick **one** channel they actually look at. If you live in Discord, just do Discord. The goal is that the alert reaches *you*, wherever you already are.

## Decide what's worth a ping

On the same screen you'll find **thresholds** — sliders for **CPU**, **Memory**, **Disk**, and **Container Memory**, each defaulting to **90%**. When a server crosses one, you get pinged. The defaults are reasonable; nudge them only if you get too many or too few alerts.

There's also a **verbosity** choice:

- **Simple (recommended)** — only pings you for things that look genuinely serious.
- **Verbose** — sends everything, including minor events.

Start on **Simple**. You can always turn it up. And the **Events** checkboxes let you choose specifics like *Node goes offline* and *Node restored* — the defaults are sensible.

## Test it before you trust it

Click **Save Settings**, then click **Send Test Alert**. A test message should arrive in your chosen channel within a few seconds. **If it doesn't arrive, fix it now** — an alert system you haven't tested is one you can't rely on. Re-check the webhook URL or token and test again.

## ✓ What you just learned

- **Settings → Alerts → Notifications** is where alerts are configured.
- Add **one** channel you actually check (Discord / Slack / Telegram / ntfy).
- Thresholds default to **90%**; verbosity **Simple** is the sane start.
- Always click **Send Test Alert** and confirm it arrives before trusting it.
