# Lock down your login

Your WolfStack dashboard is the keys to everything — every server, every container, every backup. So before you expose it to anything, let's make the front door strong. This lesson is about **who can log in**. The next one is about the server itself.

Good news: this is quick, and getting it right stops the overwhelming majority of attacks before they start.

## Where this lives

Click **Settings** (the cog, bottom-left), then the **Users & Auth** tab.

## 1. Decide how people log in

At the top you'll see the **Authentication Mode**, with three choices:

- **Linux System Login** — log in with the server's own Linux username/password (from `/etc/shadow`). The default.
- **WolfStack Users Only** — ignore Linux accounts; use WolfStack's own accounts (which can have 2FA).
- **Both** — accept either.

If you want the extra protections below (2FA in particular), **WolfStack Users** is the easiest path. Add a user with **+ Add User** — give it a **Username**, a strong **Password**, and a **Role** (**Admin** or **Viewer**). Use **Viewer** for anyone who only needs to look, not change things.

## 2. Use a strong, unique password

Change a WolfStack user's password with the **Password** button on their row. (On Linux System Login, you change it on the server itself with `passwd`.)

> A password manager generating a long random password is the single biggest upgrade you can make. Reused passwords are how most break-ins actually happen.

## 3. Turn on two-factor (2FA)

On a WolfStack user, click **Enable 2FA**. A window appears with a **QR code** — scan it with an authenticator app (Google Authenticator, Authy, etc.), enter the **6-digit code** to confirm, and that user now needs their phone as well as their password. The row shows a **2FA ENABLED** badge.

## 4. Even better — add a passkey

Open the **Passkeys** tab and click **Add passkey**. Give it a label (e.g. *MacBook Touch ID*, *YubiKey*), then approve with your fingerprint / face / security key. Now you can log in **without a password at all** — and passkeys can't be phished, which is their superpower.

> Passkeys are tied to the exact address you visit, so one registered against `https://server-a` won't work on `https://server-b`. Register one per device you actually use.

## 5. If you ever suspect a stolen session

Go to **Fleet Security** (in the Apps & Tools drawer) and click **Logout everyone, everywhere**. That invalidates every active session across the cluster — everyone (including you) has to log back in. It's the "I think someone got in" panic button.

## ✓ What you just learned

- **Settings → Users & Auth** controls who can log in (Linux, WolfStack users, or both).
- Set a **strong unique password**, then turn on **2FA** and/or add a **passkey**.
- **Fleet Security → Logout everyone** kills all sessions if you suspect a stolen cookie.
- A strong password + a second factor stops almost every real-world attack on your login.
