# Put your app on a real domain (with HTTPS)

Once you've got an app running at something like `http://192.168.1.50:3001`, the natural next wish is a proper address with a padlock: `https://app.example.com`. This is a *level-up* lesson — more moving parts than the basics — but each part is small, and WolfStack handles all three.

A real HTTPS address is just **three things lined up**:

1. a **domain** pointing at your server,
2. a **certificate** so the browser trusts it (the padlock), and
3. a **proxy route** that sends the domain to your app.

## Before you start

- A **domain you own** (e.g. `example.com`) and access to its DNS settings.
- An app already running on a server.

## Step 1 — point the domain at your server

In your domain's DNS (at your registrar or DNS host), add an **A record**: `app.example.com` → your server's **public IP address**.

> Optional, the WolfStack way: **Settings → DNS Providers → + Add Provider** — give it a **Friendly name**, pick the **Plugin** (e.g. Cloudflare), and paste the **Credentials INI** (e.g. `dns_cloudflare_api_token = …`), then **Save Provider**. This lets WolfStack prove you own the domain automatically when it fetches certificates — useful if your server isn't directly reachable on port 80.

## Step 2 — get a free HTTPS certificate

1. Open **Cluster → SSL Certificates**.
2. Choose a **Challenge type**:
   - **HTTP-01** — simplest; needs **port 80** reachable from the internet.
   - **DNS-01** — works behind a firewall and for wildcards; uses the DNS provider from step 1.
3. Enter the **Domain name** (`app.example.com`) and an **Email**, then click **Request Certificate (Let's Encrypt)**. WolfStack fetches a free, trusted certificate for you.

## Step 3 — add the proxy route

1. Open **WolfRouter → HTTP proxies** and click **+ HTTP proxy**.
2. Fill in:
   - **ID** — a short slug, e.g. `app`.
   - **Server names** — `app.example.com`.
   - **Targets** — the node(s) that should serve it.
   - **Backends** — where your app actually runs, e.g. `http://10.0.0.5:3001`.
   - **TLS** — point it at the certificate from step 2 (pick it from the list, or paste the cert/key paths), and tick **Force HTTPS (301 from :80)** so plain `http` redirects to `https`.
3. Click **Save & apply**.

Visit `https://app.example.com` — your app, on a real domain, with a padlock. 🎉

> **Don't get caught by this:** the **Reverse Proxy** tab in *Settings* is for putting **WolfStack itself** behind a proxy — not for your apps. For an app's public domain, use **WolfRouter → HTTP proxies** as above.

## ✓ What you just learned

- A real HTTPS address = **DNS → certificate → proxy route**, three small pieces.
- Point an **A record** at your server (optionally connect a **DNS Provider** for automatic certs).
- Get a free **Let's Encrypt** certificate in **Cluster → SSL Certificates**.
- Map the domain to your app in **WolfRouter → HTTP proxies**, tick **Force HTTPS**, and **Save & apply**.
