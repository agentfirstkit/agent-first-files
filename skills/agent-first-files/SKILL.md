---
name: agent-first-files
description: "Put a working directory in front of a person who is not at the machine — a root-locked, read-only projection they can browse from a phone, as a local window or a bearer-protected OpenAPI surface. Trigger when someone asks to see, browse, or share what is in a directory from elsewhere, not when you need to read a file yourself."
allowed-tools: Bash, Read
---

# Agent-First Files

Use this skill when **a person needs to look at a directory and is not at the
machine holding it** — they are on a phone, on another device, or asking you to
show them what is in a workspace.

Do not reach for it to read a file yourself. You have `Read`, `ls` and `grep`,
and they are faster and complete. `affiles` exists for the case those cannot
serve: a human eye somewhere else.

For flag-level detail ask the command: `affiles api --help` and `affiles ui
--help` return every legal shape of the call at once. This skill is behavior,
decisions and recovery only.

## The root is the decision

`--root` is required and it is the security boundary. Everything under it is
reachable by whoever holds the URL.

- Containment is a resolve-then-use check, not a kernel-enforced one. Anything
  that can create a symlink inside the root can race that check and have a read
  land outside it. **Never serve a root that a process you do not trust writes
  into** — a build output directory, an upload directory, a shared scratch
  directory. Say this when a person asks for one.

- Choose the **narrowest** directory that answers the question. A person asking
  about a project gets the project, not its parent.
- **Never `$HOME`, never `/`, never a directory you have not looked in.** If a
  person asks for one of those, say what it would expose and offer the narrower
  root instead.
- The root cannot be changed while the process runs. A different root is a
  different process — do not build a wrapper that restarts one on request.

## Excluding is the caller's judgement, not a built-in list

`--exclude` hides matches entirely, listings included. There is deliberately no
default list of dangerous filenames, because one that misses `.env.local.bak`
teaches people to trust it.

So: before serving a root you have not served before, **look at what is in it**.
If you see credentials, keys, or personal data that the person asking has not
asked to share, name them and propose `--exclude` patterns. Do not serve first
and mention it afterwards.

An excluded path answers exactly as a path that never existed. That is
deliberate; do not try to give a caller a better error, and do not report to a
person that a specific excluded file exists.

## Read-only, and it stays that way

There is no write surface. When someone asks to edit, upload, rename or delete
through affiles, the answer is that this tool does not do that — then do the
edit yourself with your own tools if that is what they wanted. Never stand up a
second server to fill the gap.

## Which delivery

- `affiles ui --root <PATH>` opens a window on **this** machine. AFUI owns the
  browser, its disposable profile, the credential and the security headers.
- That default is not fixed — it follows `AFUI_DELIVERY` when `--mode` is not
  given. Inside a shell that already exports `AFUI_DELIVERY=session` (a
  terminal published for a person who is not at this machine, for instance),
  `affiles ui --root <PATH>` with no flag at all does the right thing on its
  own: it publishes instead of popping a window nobody there would see. An
  explicit `--mode` always wins over the environment, and typing `--mode
  window` there opens one anyway.
- `affiles ui --root <PATH> --mode session` publishes the session and opens
  nothing. **This is the one to reach for when the person is not here** — they
  asked to see a directory from a phone, so a browser window on this machine is
  something nobody will look at and something a headless machine cannot open at
  all. It runs until stopped, so start it the way you would start a server.
  **Before you publish, apply the same judgement `--root` already got.** The
  `afui session serve` URL is a master key to every session on this machine,
  not just this one — publishing adds this root's entire contents to what that
  key is worth. Confirm the root is one the person would be fine with *anyone*
  holding that URL seeing, not only the person who asked.
- `affiles ui --root <PATH> --mode link` returns a direct LAN URL and needs no
  `afui` command on the receiving device. It is a bearer capability for the
  whole root: share it only through a trusted channel, never paste it into a
  log, and never expose its listener directly to the Internet. The URL is an
  AFUI-owned page: AFUI applies its global `attention.idle_timeout_s` and
  `attention.grace_period_s` policy, including the visible warning and renew
  action.
- `affiles api serve --root <PATH>` is the contract, for a caller that is a
  program. The bearer credential comes from `AFFILES_API_ACCESS_TOKEN_SECRET`
  or `--access-token-secret`; it never appears in output, and there is no
  query-string form of it.
- For a person on **another device**, choose `link` for one direct root or
  `session` for an aggregated `afui session serve` view. Crossing networks is
  still WireGuard, Tailscale, an SSH tunnel or a TLS reverse proxy; never
  suggest exposing either listener directly to the Internet.

## Recovery

- `root_unusable` — the path does not exist, is not a directory, or cannot be
  canonicalized. Report the path; do not silently fall back to the current
  directory.
- `entry_not_found` — missing, excluded, or outside the root, and you cannot
  tell which. Do not probe to find out which one it was.
- `not_text` — read it through the bytes route instead, or tell the person it is
  binary. Do not decode it and present a guess.
- `is_a_directory` / `not_a_directory` — the other route is the one they want;
  the hint says which.
- The window is live: it batches changed paths for 250 ms and re-reads only the
  open directories affected by that batch. A reconnect or a lagged event stream
  requests one authoritative full resync. If somebody reports a stale tree,
  check the page's status line — `not live` means the AFUI runtime connection
  dropped. Do not tell them to reload as a first move, and do not offer to poll
  on their behalf.
- Directory cursors are opaque. Pass `next_cursor` back byte-for-byte; never
  decode, edit, or manufacture one. `invalid_cursor` means start that listing
  again without a cursor.
- `watch_unavailable` — the projection has no watcher, so browsing works and
  updates do not. Say that plainly rather than leaving them to discover it.
- `ui_frontend_unusable` — a workspace frontend override cannot be loaded.
  Surface the message. `AFUI_SAFE_MODE=1` ignores overrides and is the right
  setting when the person only needs affiles' own page.
- `ui_delivery_unavailable` — `AFUI_DELIVERY` is not one of `window`, `link`,
  or `session`. Correct or unset it; do not silently retry in window mode.
