# Agent-First Files

Show a directory on your machine to someone who is not at it — one folder,
read-only, and nothing above it.

`agent-first-files` lists directories, reads files as text or bytes, and refuses
everything outside its root, behind a bearer-protected loopback HTTP server with
a generated OpenAPI 3.2 contract. Its CLI can also open the same projection as a
trusted local window.

> **Ask your agent:** "Let me look at this project from my phone."

## The problem: an agent can read a directory, a person elsewhere cannot

An agent working on your machine already has `ls`, a file reader and a grep.
The one thing it has no way to do is show *you* what is in a directory when you
are not there.

So it improvises, and the improvisations are all bad in the same way. It
flattens a tree into a chat message that is stale the moment it is sent. It
pastes file contents into a conversation. Or it writes a little file server —
with a port, a path traversal bug, and no idea what a symlink is.

affiles is that missing surface and only that: one root, read-only, over a
contract, with a page attached.

## The root is the boundary

One process, one root, fixed before anything is served. Every path is relative
to it, and the upper bound on what a leaked URL can show is the root itself.

`--root` is required and has no default. A convenient "current directory"
becomes a home directory the first time somebody runs it after `cd ~`, and a
default that is occasionally catastrophic is not worth the keystrokes it saves.

Three rules keep a path inside the root, each there because of a specific way
the obvious version fails:

- comparison is by **path component**, never by string prefix — `/srv/root` is a
  prefix of `/srv/root-evil` as text and is not one as a path;
- containment is checked **after** canonicalization, so an intermediate symlink
  cannot smuggle a path out before the last component is looked at;
- an excluded path, a path outside the root, and a path that was never there all
  answer identically. A refusal you can tell apart from an absence is an oracle
  for what exists.

A symlink whose target stays inside the root is followed, because a source tree
full of them has to remain browsable. One that leaves is listed, named, and
never opened — you should be able to see that something is there without it
being reachable. `--no-symlinks` follows none at all.

### What the root does and does not promise

Those three rules are checks on a resolved path, and the file is opened by that
path a moment later. Between those two moments, anything able to write inside
the root can replace a directory with a link pointing out of it, and the open
lands on the other end. A file read notices afterwards — the opened file's
identity is compared with the resolved one and a substitution is refused — but a
directory listing has no equivalent check, and on Windows the identity
comparison is not implemented at all.

Closing this needs the whole walk to happen against an open directory handle:
`openat2` with `RESOLVE_BENEATH` on Linux, a component-at-a-time `openat` loop
on other unixes, handle-relative opens on Windows. Until that is in place, read
the boundary as: **the root is the upper bound on what a leaked URL can name,
and it holds against anything that cannot write inside the root.**

In practice: serve a source tree, a document directory, a build you own. Do not
serve a directory an untrusted process writes into — an upload target, a shared
scratch directory, another user's workspace.

## It stays true while you watch it

A tree left open on a phone would otherwise become a slowly aging picture of a
workspace. The window keeps a change stream open and re-reads exactly the
directories that changed.

Watching follows the same rule the tree does: **a directory is watched exactly
while somebody has it open.** Nothing is recursive — a recursive watch over a
repository registers one watch per directory on Linux, which a `node_modules`
exhausts outright, and it makes this process do work for parts of the tree
nobody has looked at. Collapse a directory and it stops costing anything.

## What it will not do

- **Write.** No create, rename, delete or upload. Your agent already has those,
  and a writable surface reachable from a phone is a blast radius nobody asked
  for.
- **Redact your files.** Only affiles' own envelope fields go through AFDATA
  redaction. Scrubbing a person's own file would corrupt the thing they came to
  read, and it would not work anyway.
- **Carry a built-in list of dangerous filenames.** A list that misses
  `.env.local.bak` is worse than none, because people rely on it. `--exclude`
  takes your own patterns — gitignore's shape, with one difference: excluding a
  directory's contents excludes the directory too, so hiding something does not
  leave you publishing its name.
- **Render your files as markup.** No HTML preview, no Markdown rendering, no
  PDF viewer. The page shows text as text and images as images; a `.html` file
  is source. It is framed inside a session host, and the sandbox is the last
  line, not a licence to hand it attacker-controlled markup.
- **Be a transport.** It binds a port. Reaching that port from another device is
  WireGuard, Tailscale, an SSH tunnel or a TLS reverse proxy — mature things
  that already exist and are not this.

## Install the CLI

```bash
# prebuilt binary
brew install agentfirstkit/tap/affiles   # macOS / Linux
scoop bucket add agentfirstkit https://github.com/agentfirstkit/scoop-bucket && scoop install affiles   # Windows

# or from crates.io
cargo install agent-first-files --locked --features api
```

Prebuilt archives are also available from
[GitHub Releases](https://github.com/agentfirstkit/agent-first-files/releases).

The `affiles` target declares `required-features = ["api"]`, so a plain
`cargo install agent-first-files` installs nothing — and says so, naming the
flag, rather than leaving a working-looking install with no executable.
Depending on this crate as a library needs no feature at all, which is the whole
point of the gate: the core is `std` only, with no async runtime and no HTTP.

## CLI

`affiles` emits one AFDATA protocol event per run. JSON is the default; YAML and
plain output are also available.

```bash
# Open a window on this machine, hiding what should not leave it.
affiles ui --root ~/code/project --exclude '*.pem' --exclude .env

# A LAN URL for a device with no AFUI on it. Bearer capability: whoever holds
# it can browse the entire root until AFUI's unattended-page policy lapses.
affiles ui --root ~/code/project --mode link

# Publish and open nothing here — for a display-less machine, or a person who
# is somewhere else entirely.
affiles ui --root ~/code/project --mode session

# The contract, for a caller that is a program.
export AFFILES_API_ACCESS_TOKEN_SECRET='replace-with-at-least-32-bearer-safe-characters'
affiles api serve --root ~/code/project --port 9422

# Write the OpenAPI document and its standalone schemas.
affiles api export --directory openapi --force
# {"kind":"result","result":{"file_count":10,"openapi_path":"openapi/openapi.json",...},"trace":{}}
```

`--mode link` keeps the files provider on loopback and hands back an AFUI-owned
URL that needs no second CLI on the receiving device. There is no TLS and no
Internet exposure built in; hand the URL over through a trusted channel and a
trusted network.

`--mode session` publishes and opens nothing, so the command itself is the
bound — it runs until you stop it. Put it on [`afui session
serve`](https://github.com/agentfirstkit/agent-first-ui) alongside every other
session on the machine and cross the gap with a tunnel you already trust. Use
`link` when the other device should open this one root directly.

## Agent Skill

Then install the embedded [Agent Skill](skills/agent-first-files/SKILL.md) so
the agent follows affiles' behavior rules — which root to serve, what a refusal
means, and why it must never be pointed at a directory something untrusted
writes into. `skill install` targets Codex, Claude Code, opencode and Hermes;
`skill status` reports whether each install is present, valid and current:

```bash
affiles skill install --agent all --scope workspace
affiles skill status
```

## Replacing the page

The page is a MiniJinja template and it is yours to restructure:

```sh
afui frontend init --provider-id affiles --ui-kind files
afui frontend enable
```

Two things stay affiles': the elements the runtime binds to — take their ids
from `document.elements`, because a page that drops one is reported as a broken
override instead of opening as a browser that shows nothing — and the script,
which a frontend cannot supply at all.

See [docs/reference.md](docs/reference.md) for the API surface and the full
override contract.

## Docs

- [Reference](docs/reference.md) — API surface, delivery, override contract
- [CLI](docs/cli.md) — generated command and flag reference

## License

MIT
