# Reference

Detail that the README deliberately leaves out. For the command and flag
listing, see [cli.md](cli.md); for the behavioural rules an agent should follow,
see the agent skill.

## HTTP API

`api serve --mode local` (the default) binds `127.0.0.1`. `--mode lan` binds all
interfaces for a trusted IPv4 network and publishes this machine's LAN address.
There is no TLS and no Internet exposure built in.

Public for discovery: `/health`, `/openapi.json`, and the standalone JSON
Schemas under `/schemas/`. Everything under `/v1` requires
`Authorization: Bearer ...` and never accepts a credential in a query string.

The root path is a user value, so it lives behind the credential rather than in
the health response — an unauthenticated caller learns that something is serving
here, not what.

Domain responses are AFDATA envelopes and pass through AFDATA redaction on the
way out. One route is not an envelope and cannot be: `/v1/files/bytes` returns
the file itself. It stays inside the contract — OpenAPI 3.2 describes a binary
body perfectly well — with a media type taken conservatively from the extension
and never sniffed from content, `nosniff`, and an attachment disposition.

A path is a **query parameter** rather than a URL path segment, because a
filesystem path is not a URL path: spelling it as one produces exactly the
ambiguity this API must not have.

Every read is bounded by an explicit ceiling on any single response, so one
enormous file cannot become the caller's problem.

## Delivery

Delivery is hosted by [Agent-First
UI](https://github.com/agentfirstkit/agent-first-ui), which owns the browser
process and disposable profile for `window`, the outer page and attention policy
for `link`, and the registry entry for `session`.

For `link`, AFUI owns the visible attention heartbeat, the warning, the grace
period, the proxy and the public credential. By default it warns after 15
unattended minutes and lapses 5 minutes later; the global
`attention.idle_timeout_s` and `attention.grace_period_s` settings control both
this link and `afui session serve`.

## Override contract

`ui_api_version` is `1`. A frontend may supply `templates/page.html.j2`,
`style.css` and `assets/**`, each independently; a file it does not supply is
affiles'.

Two things are not the frontend's:

- **The elements the runtime binds to.** Take their ids from
  `document.elements` rather than typing them out. A page that drops a required
  element is reported as a broken override; it never opens as a browser that
  shows nothing.
- **The script.** `<!-- affiles:trusted-runtime -->` is where affiles splices in
  `app.js`. A frontend cannot supply JavaScript at all — AFUI refuses a file
  whose name says it is a script, and refuses one hidden inside a template.

A frontend affiles cannot load ends the command with `ui_frontend_unusable` and
opens no window; it is never a quietly substituted built-in page.
`AFUI_SAFE_MODE=1` ignores every override.

## Exclusions

`--exclude` takes gitignore-shaped patterns, with one deliberate difference:
excluding a directory's contents excludes the directory too. Hiding something
should not leave you publishing its name.

An excluded path answers exactly as a path outside the root does, and exactly as
a path that was never there does. There is one refusal, and it distinguishes
nothing.
