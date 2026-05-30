# Restore from a backup

This is the other half of backups — and honestly the more important half. **A backup you have never restored is just a hope.** Let's make sure you can actually get your stuff back, and let's prove it while nothing's on fire.

There are two ways to restore, depending on where the backup lives.

## Restore from the Backups list

1. Go to your **server → Backups** and scroll to the **Backup History** table.
2. Find a backup with a green **Completed** status. Click **Restore** on its row.
3. The **Restore backup** window opens:
   - **Restore as container name** (for LXC) — it defaults to the original name. **Change it to restore as a separate *copy***. This is the safe way to test a restore without touching the thing that's currently running.
   - **Replace the target if it already exists** — leave this **unticked** to restore as a new copy. Tick it **only** when you really mean to overwrite the existing one (it gets stopped and replaced).
   - **Target Proxmox storage** (on Proxmox) — where the restored container's disk goes. The default is fine.
4. Click **Restore** and watch the live progress. You'll get a green **✅** when it's done.

> If you see *"The target already exists"*, it's protecting you from an accidental overwrite — either tick **Replace** (to overwrite) or restore under a different name.

## Restore from a PBS snapshot

If you back up to a **Proxmox Backup Server**, your restores come from there instead:

1. On the **Backups** page, find the **PBS Snapshots** section (it shows **✓ Connected (N snapshots)** when PBS is set up).
2. Pick the snapshot you want by name/date and click **⬇️ Restore**.
3. The **Restore PBS snapshot** window works the same way — **Restore as container name** (change it to make a copy) and the **Replace** checkbox. Click **Restore** and watch the live **%** progress to **✅**.

## The five-minute habit that saves you

> **Do a test restore right now.** Restore one backup under a *new* name, confirm it actually comes up and works, then delete the copy. That's it — now you *know* your backups are real. Most people only discover theirs were broken at the exact worst moment. Don't be most people.

## ✓ What you just learned

- Restore from **Backup History** (the **Restore** button) or from **PBS Snapshots** (**⬇️ Restore**).
- **Restore under a different name** to test safely; tick **Replace** only when you intend to overwrite.
- A restore you've actually tested is the difference between a backup and a false sense of security — test one today.
