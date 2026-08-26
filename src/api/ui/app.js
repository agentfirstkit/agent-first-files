'use strict';

/* Browsing one root, on a phone.
 *
 * Three rules run through this file.
 *
 * Nothing is fetched until somebody asks for it. The tree starts as the root's
 * own entries and grows one directory at a time: expanding a node asks for that
 * directory and no other, and a directory long enough to be paged grows one
 * page at a time under a control of its own. A browser that read the whole tree
 * up front would be unusable on the first repository with a `node_modules` in
 * it, and would make the machine do that work whether or not anyone looked.
 *
 * Nothing from the workspace becomes markup. Every value that came out of a
 * file or off a filesystem is assigned with `textContent` or set as an
 * attribute on an element this file created — never parsed as HTML. That is why
 * there is no HTML-assigning sink anywhere here, and why a test fails the build
 * if one appears: a directory listing is attacker-influenced input the moment
 * somebody can create a file, and a file's contents always are.
 *
 * What is shown stays true, or says it is not. AFUI replaces one retained state
 * whenever the watched filesystem may have changed. A live replacement names
 * the directories affected by one coalesced burst. A reconnect receives the
 * newest retained replacement before AFUI calls the session live, and the page
 * treats that boundary as a full resync because intermediate bursts may have
 * been replaced while it was away.
 *
 * The server decides what is reachable. This page sends back the path it was
 * given in a listing, verbatim; it never builds one by concatenating, never
 * resolves `..`, and never guesses that a sibling exists. Everything it asks
 * for is refused the same way whether it is missing, excluded, or outside the
 * root.
 *
 * A file is a place. AFUI owns what that means in a browser — one history
 * entry, both directions through it, Escape, the keyboard put back where it
 * came from, and the navigation control of a window frame this page may be
 * running inside. What stays here is what a place is on *this* page: which
 * file the address names, and what showing one and taking it down look like.
 * Everything else the page does is a projection of what is already on screen
 * and only ever replaces the address. */

(() => {
  const byId = id => document.getElementById(id);
  const rootName = byId('root-name');
  const tree = byId('tree');
  const emptyState = byId('empty-state');
  const status = byId('status');
  const viewer = byId('viewer');
  const viewerTitle = byId('viewer-title');
  const viewerMeta = byId('viewer-meta');
  const viewerBody = byId('viewer-body');
  const viewerClose = byId('viewer-close');

  const IMAGE_EXTENSIONS = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'bmp', 'ico'];

  /* How many directories' expand state is kept in the URL.
   *
   * The fragment records what is open, never what is inside it, so its size
   * tracks how deep and how wide a person has gone rather than how large any
   * one directory is. Past this many, the oldest expansion is dropped rather
   * than the fragment growing without bound — and dropping it is silent,
   * because a URL that is merely a little less specific is not a failure. */
  const MAX_REMEMBERED_OPEN = 50;
  /** Root-relative path -> the state of one directory this page has open. */
  const open = new Map();
  /** The file the viewer is showing, so a change to it can be picked up too. */
  let viewing = null;
  /** Invalidates a slower read when the person closes or opens another file. */
  let viewRequest = 0;
  /** The AFUI body currently held for an image preview. */
  let viewBlob = null;
  let started = false;
  let watchState = 'unknown';
  let sessionRuntime = null;
  /** AFUI's own word for the session runtime, carried by whatever says it. */
  let connection = 'connecting';
  /** A connection gap may have replaced intermediate watcher batches. */
  let resyncRequired = true;

  /* This page's head, and the one it may be inside.
   *
   * A framed page is a page with two heads saying the same three things: whose
   * program this is, what it is on, and how it is going. The first two are the
   * frame's already — from the listener rather than from here, which is why
   * this page never sends them — so being told there is a head out there means
   * dropping this one and handing up only the third. */
  const pageHead = afui.frame({
    onHead: head => {
      document.body.dataset.frameHead = head ? 'true' : 'false';
    },
  });

  function say(message) {
    status.textContent = message;
    pageHead.status(message, connection);
  }

  function sizeOf(entry) {
    if (entry.kind === 'directory') return '';
    const bytes = Number(entry.size_bytes) || 0;
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  /* Filesystems speak RFC 3339; people scan dates in their own locale. The
   * exact timestamp stays in the title for anyone who needs it. */
  function modifiedOf(value) {
    if (!value) return '';
    const instant = new Date(value);
    if (Number.isNaN(instant.getTime())) return value;
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    }).format(instant);
  }

  function setRowMeta(meta, entry) {
    const note = noteOf(entry);
    meta.textContent = note || [sizeOf(entry), modifiedOf(entry.modified_rfc3339)].filter(Boolean).join(' · ');
    meta.title = note ? '' : (entry.modified_rfc3339 || '');
  }

  /* What a person is told about an entry they cannot open.
   *
   * Said rather than left to be inferred from a row that does nothing when
   * tapped: a link out of the root and a name this API cannot address are
   * different facts, and both are facts about the directory. */
  function noteOf(entry) {
    if (entry.unsupported === 'outside_root') return 'link outside the root';
    if (entry.unsupported === 'non_utf8_name') return 'name is not text';
    if (entry.unsupported === 'unsupported_kind') return 'not a file or directory';
    return '';
  }

  /* Tell the server exactly what is on screen.
   *
   * Sent on every expand and collapse, and it is the whole set rather than a
   * delta — the page knows the answer, so there is nothing for the two sides to
   * disagree about. A directory that is collapsed stops being watched, which is
   * what keeps this bounded on a tree nobody could hold open all of. */
  async function declareInterest() {
    try {
      await sessionRuntime.call({type: 'set_watch', paths: [...open.keys()]});
    } catch (error) {
      // Retained state reports whether this page can be live; one failed
      // declaration is not worth adding a second, contradicting voice.
    }
  }

  // AFUI owns correlation, replay and caller-safe failures. The page supplies
  // only the domain action and checks that the typed reply matches it.
  async function ask(type, parameters) {
    try {
      const reply = await sessionRuntime.call({type, ...parameters});
      if (!reply || reply.type !== type) throw new Error('unexpected_ui_reply');
      return reply;
    } catch (failure) {
      const error = new Error(failure.code || failure.message || 'ui_action_failed');
      error.code = failure.code || 'ui_action_failed';
      throw error;
    }
  }

  /* One row, and the empty list its children will go in.
   *
   * The child list is created collapsed and stays empty until the first
   * expansion, so a node costs one element until somebody is interested in it. */
  function node(entry, depth) {
    const item = document.createElement('li');
    item.className = 'node';
    item.dataset.kind = entry.kind;
    item.setAttribute('role', 'treeitem');
    item.setAttribute('aria-level', String(depth + 1));
    if (entry.unsupported) item.dataset.unsupported = entry.unsupported;

    const openable = entry.readable;
    const row = document.createElement(openable ? 'button' : 'span');
    row.className = 'row';
    row.style.paddingLeft = `${8 + depth * 14}px`;

    const twisty = document.createElement('span');
    twisty.className = 'twisty';
    twisty.setAttribute('aria-hidden', 'true');
    // A directory always offers the control; whether it has anything in it is
    // something only expanding can answer, and asking ahead of time would be a
    // stat of every entry in the tree to draw one glyph.
    twisty.textContent = entry.kind === 'directory' && openable ? '▸' : '';
    row.append(twisty);

    const name = document.createElement('span');
    name.className = 'row-name';
    // textContent, always: a file called `<img onerror=…>` is a file somebody
    // can create.
    name.textContent = entry.name;
    row.append(name);

    const meta = document.createElement('span');
    meta.className = 'row-meta';
    setRowMeta(meta, entry);
    row.append(meta);

    item.append(row);

    const children = document.createElement('ul');
    children.className = 'children';
    children.setAttribute('role', 'group');
    children.hidden = true;
    item.append(children);

    if (openable) {
      row.type = 'button';
      if (entry.kind === 'directory') {
        item.setAttribute('aria-expanded', 'false');
        row.addEventListener('click', () => toggle(entry, item, children, twisty, depth));
      } else {
        row.addEventListener('click', () => view(entry));
      }
      item.dataset.path = entry.path;
    }
    return item;
  }

  /* Expand, or collapse.
   *
   * Collapsing keeps what was already fetched. Re-expanding a directory a
   * person is comparing against another is then free, and the bound on how much
   * this page holds is the paging below rather than how often somebody clicks. */
  async function toggle(entry, item, children, twisty, depth) {
    const expanded = item.getAttribute('aria-expanded') === 'true';
    if (expanded) {
      item.setAttribute('aria-expanded', 'false');
      children.hidden = true;
      twisty.textContent = '▸';
      open.delete(entry.path);
      declareInterest();
      updateFragment();
      return;
    }
    item.setAttribute('aria-expanded', 'true');
    children.hidden = false;
    twisty.textContent = '▾';
    open.set(entry.path, {container: children, depth: depth + 1});
    declareInterest();
    updateFragment();
    if (children.dataset.loaded === 'true') return;
    twisty.textContent = '…';
    const loaded = await fill(children, entry.path, depth + 1, null);
    twisty.textContent = '▾';
    if (loaded) children.dataset.loaded = 'true';
  }

  /* Read one directory again, keeping everything the person still has open.
   *
   * Rebuilding the node would be one line and would collapse every expanded
   * directory under it, which on a tree somebody has spent a minute opening is
   * the change destroying the thing it was supposed to keep true. So entries
   * are matched by path: the ones that are still there keep their subtree and
   * only their line is refreshed, the new ones are inserted in order, and the
   * ones that are gone take their subtree with them.
   *
   * Only the first page is re-read. A directory somebody paged deep into
   * returns to its first page and its own control; re-fetching every page a
   * person had loaded would turn one `git checkout` into a burst of them. */
  async function refresh(path) {
    const held = open.get(path);
    if (!held) return;
    let body;
    try {
      body = await ask('browse', {path});
    } catch (error) {
      // Gone, or refused. Its parent's own refresh removes the row; nothing to
      // do here but leave what is on screen alone.
      return;
    }
    const container = held.container;
    const existing = new Map();
    for (const item of container.querySelectorAll(':scope > .node')) {
      existing.set(item.dataset.path, item);
    }
    const kept = new Set();
    let cursor = null;
    for (const entry of body.listing.entries) {
      kept.add(entry.path);
      const previous = existing.get(entry.path);
      const rebuilt = previous && previous.dataset.kind !== entry.kind;
      const item = previous && !rebuilt ? previous : node(entry, held.depth);
      if (previous && !rebuilt) refreshRow(item, entry);
      // `insertBefore` with the running cursor puts every entry in the server's
      // order without disturbing the ones that did not move.
      container.insertBefore(item, cursor ? cursor.nextSibling : container.firstChild);
      cursor = item;
    }
    for (const [entryPath, item] of existing) {
      if (kept.has(entryPath)) continue;
      forget(entryPath, item);
      item.remove();
    }
    const previousMore = container.querySelector(':scope > .more');
    if (previousMore) previousMore.remove();
    const stale = container.querySelector(':scope > .failed');
    if (stale) stale.remove();
    if (body.listing.next_cursor) appendMore(container, path, held.depth, body.listing.next_cursor);
    if (body.listing.entry_count === 0) appendNote(container, 'empty');
    if (path === '') say(`${body.listing.entry_count} at the root`);
  }

  /* Only the line changed, so only the line is rewritten — the row element is
   * the same one, which is what keeps its children and its expanded state. */
  function refreshRow(item, entry) {
    const meta = item.querySelector(':scope > .row > .row-meta');
    if (!meta) return;
    setRowMeta(meta, entry);
  }

  /* A row that leaves takes its subtree's interest with it, or the page would
   * keep asking the server to watch directories nobody can see. */
  function forget(path, item) {
    open.delete(path);
    for (const nested of item.querySelectorAll('.node')) open.delete(nested.dataset.path);
  }

  /* One page of one directory, appended where it belongs.
   *
   * `cursor` is only ever one this API handed out. When it hands back another,
   * the directory keeps its own control for the next page — the rest of a large
   * directory is not something to fetch because it exists. */
  async function fill(container, path, depth, cursor) {
    // `:scope >` so paging one directory does not remove the control belonging
    // to an expanded directory inside it.
    const previous = container.querySelector(':scope > .more');
    if (previous) previous.remove();
    let body;
    try {
      body = await ask('browse', cursor ? {path, cursor} : {path});
    } catch (error) {
      appendNote(container, error.message === 'entry_not_found' ? 'not found' : error.message);
      return null;
    }
    for (const entry of body.listing.entries) container.append(node(entry, depth));
    if (body.listing.entry_count === 0 && !cursor) appendNote(container, 'empty');
    if (body.listing.next_cursor) {
      appendMore(container, path, depth, body.listing.next_cursor);
    }
    return body;
  }

  function appendMore(container, path, depth, cursor) {
    const more = document.createElement('li');
    more.className = 'more';
    // Read back by `locateChild` above, so restoring from the URL can page
    // through a long directory the same way a tap on this button would.
    more.dataset.cursor = cursor;
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'row';
    button.style.paddingLeft = `${8 + depth * 14}px`;
    button.textContent = 'Show more';
    button.addEventListener('click', () => {
      button.textContent = 'Loading…';
      fill(container, path, depth, cursor);
    });
    more.append(button);
    container.append(more);
  }

  /* An empty directory, or one that refused. Both are facts about the node, so
   * both are said inside it rather than as a page-level message. */
  function appendNote(container, text) {
    const note = document.createElement('li');
    note.className = 'failed';
    note.setAttribute('role', 'treeitem');
    note.textContent = text;
    container.append(note);
  }

  /* Taking the file down. Called by the place, never directly: the button,
   * Escape, the phone's own back gesture and a frame's navigation control are
   * all one way out, and this runs once at the end of it. */
  function close() {
    viewRequest += 1;
    viewing = null;
    pageHead.title(null);
    releaseViewBlob();
    viewer.hidden = true;
    delete document.body.dataset.viewing;
    viewerBody.replaceChildren();
    updateFragment();
  }

  /* The file, as a place a person can be in, leave, and come back to.
   *
   * `at` and `show` are how this page arrives somewhere it did not open by
   * hand — a person going forward again, or an address they were sent. Both
   * read the file off a row the tree has already listed rather than off the
   * address, for the same reason nothing else here builds a path: a fragment
   * is a person's to edit, and a name out of one has never been shown to be
   * something they may see. */
  const filePlace = afui.place({
    at: () => (parseFragment() || {}).viewPath || null,
    show: path => {
      if (viewing && viewing.path === path) return;
      findLoadedEntry(path).then(entry => {
        if (entry) view(entry);
      });
    },
    hide: close,
    /* A frame that draws the way out has put one where the person's window
     * keeps it. Whether this page's own control is then a second one is a
     * question about width — over the tree it is the same gesture twice,
     * beside the tree it closes a pane nobody navigated away from — so the
     * word goes on the page and the stylesheet answers it. The width is
     * written down once, where the rest of the width is. */
    onFrame: frame => {
      document.body.dataset.frameNavigation = frame.navigation ? 'true' : 'false';
    },
  });

  function releaseViewBlob() {
    if (!viewBlob) return;
    sessionRuntime.releaseBlob(viewBlob);
    viewBlob = null;
  }

  /* Reconstructing this page from nothing but its own URL.
   *
   * An iframe holding this page gets rebuilt without warning — a card left
   * idle in `afui session serve` loses attention and comes back later, and
   * because the watch range is exactly the expand range, a rebuilt iframe
   * would otherwise lose what the person had selected. The address is the one
   * thing that survives that rebuild, so it carries view selection while AFUI
   * restores the live session state. */

  /* One entry's own path, one level up. Shared by the viewer, which needs to
   * know what a change to its directory looks like, and by restoring below,
   * which needs to open every ancestor before the entry itself. */
  function parentOf(path) {
    const cut = path.lastIndexOf('/');
    return cut === -1 ? '' : path.slice(0, cut);
  }

  /* A parent listing change can remove or rename an open subtree. Refresh the
   * changed directory and every open descendant, but never an unrelated
   * branch. The empty path is the root and therefore contains every path. */
  function atOrUnder(path, directory) {
    return directory === '' || path === directory || path.startsWith(`${directory}/`);
  }

  /* The one child of `container` already rendered at this path, or none.
   *
   * A lookup by attribute rather than a CSS selector built from the path: a
   * file is free to be named with a quote or a bracket in it, and turning that
   * into a selector would be one escaping mistake away from matching the wrong
   * row, or throwing. */
  function childNode(container, path) {
    for (const item of container.querySelectorAll(':scope > .node')) {
      if (item.dataset.path === path) return item;
    }
    return null;
  }

  /* A path, and every directory that has to be open before it can be reached.
   * Defensive rather than trusting that a saved fragment already lists every
   * ancestor — this page always writes it that way, but the URL is a person's
   * to edit, and a hand-shortened one should still restore as far as it can. */
  function withAncestors(paths) {
    const all = new Set();
    for (const path of paths) {
      // These are root-relative identifiers, not filesystem paths to
      // normalise. Ignoring a malformed branch keeps `/secret`, `a//b`, `.`
      // and `..` from being silently reinterpreted as a different valid one.
      const segments = path.split('/');
      if (segments.some(segment => !segment || segment === '.' || segment === '..')) continue;
      for (let end = 1; end <= segments.length; end += 1) {
        all.add(segments.slice(0, end).join('/'));
      }
    }
    return all;
  }

  /* What belongs in the URL: which directories are open and what is being
   * viewed — never their contents. A snapshot of contents would be wrong the
   * moment a file changed; a set of places to ask about again cannot be, since
   * there is nothing in it to go stale.
   *
   * The viewed file's own ancestors are kept outside the cap: they are never
   * more than as deep as the tree itself, and losing one would strand the one
   * thing actually being looked at. */
  function fragmentState() {
    const required = new Set();
    if (viewing) {
      const segments = viewing.path.split('/');
      for (let end = 1; end < segments.length; end += 1) {
        required.add(segments.slice(0, end).join('/'));
      }
    }
    const remembered = [...open.keys()].filter(candidate => candidate !== '');
    const rest = remembered.filter(candidate => !required.has(candidate));
    const room = Math.max(0, MAX_REMEMBERED_OPEN - required.size);
    // `open` is insertion-ordered and an entry is deleted and re-added on
    // every collapse/expand, so the tail of this array is whatever was
    // interacted with most recently — which is what "remembered" should mean
    // here, rather than whatever happened to be opened first.
    const capped = rest.slice(Math.max(0, rest.length - room));
    return {
      openPaths: [...required, ...capped],
      viewPath: viewing ? viewing.path : null,
    };
  }

  /* `history.replaceState` for everything but the file: the fragment is a
   * projection of what is already on screen, not a new place that was visited.
   * An expand is not somewhere a person came from — one entry per expand would
   * make leaving a page somebody opened from a message take a dozen taps. */
  function updateFragment() {
    const {openPaths, viewPath} = fragmentState();
    const params = new URLSearchParams();
    for (const path of openPaths) params.append('open', path);
    if (viewPath !== null) params.set('view', viewPath);
    const hash = params.toString();
    history.replaceState(null, '', `${location.pathname}${location.search}${hash ? `#${hash}` : ''}`);
  }

  function parseFragment() {
    const raw = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash;
    if (!raw) return null;
    const params = new URLSearchParams(raw);
    const openPaths = params.getAll('open').filter(Boolean);
    const viewPath = params.get('view');
    if (openPaths.length === 0 && !viewPath) return null;
    return {openPaths, viewPath};
  }

  /* The row for `path` under `parent`, paging `parent.container` the same way
   * a tap on "Show more" would until it turns up or there is no more to ask
   * for. A directory a person had paged deep into is not "gone" just because
   * its first page does not contain the name being restored. */
  async function locateChild(parent, path) {
    let item = childNode(parent.container, path);
    while (!item) {
      const more = parent.container.querySelector(':scope > .more');
      if (!more) return null;
      // eslint-disable-next-line no-await-in-loop -- each page depends on the last.
      await fill(parent.container, parentOf(path), parent.depth, more.dataset.cursor);
      item = childNode(parent.container, path);
    }
    return item;
  }

  /* Open one directory the same way a tap would, or say it could not.
   *
   * Driving the same `toggle` a click drives is what keeps this on the one
   * ordinary route: there is no second way to expand a directory that paging
   * or exclusion could disagree with, and nothing here reads a raw path out of
   * the URL and hands it to the filesystem — every name came out of a listing
   * this page already fetched and was already allowed to see. */
  async function openPath(path) {
    const parent = open.get(parentOf(path));
    if (!parent) return false;
    const item = await locateChild(parent, path);
    if (!item || item.dataset.kind !== 'directory') return false;
    const children = item.querySelector(':scope > .children');
    if (item.getAttribute('aria-expanded') !== 'true') {
      const twisty = item.querySelector(':scope > .row > .twisty');
      await toggle({path}, item, children, twisty, parent.depth);
    }
    return children.dataset.loaded === 'true';
  }

  /* What `view` needs for the file the URL named, read off the row restoring
   * its directory already produced — never invented from the path string
   * alone, for the same reason `openPath` never fetches one either. */
  async function findLoadedEntry(path) {
    const parent = open.get(parentOf(path));
    if (!parent) return null;
    const item = await locateChild(parent, path);
    const name = item && item.querySelector(':scope > .row > .row-name');
    return name ? {path, name: name.textContent} : null;
  }

  async function restorePaths(paths, opener) {
    let complete = true;
    for (const path of paths) {
      // eslint-disable-next-line no-await-in-loop -- each layer depends on the last.
      if (!(await opener(path))) complete = false;
    }
    return complete;
  }

  /* Rebuild what the URL says was open and being viewed, one directory at a
   * time through `openPath`.
   *
   * Failing partway is not an error: whatever a person deleted, excluded, or a
   * hand-edited fragment invented simply cannot be found among a real listing,
   * so that branch stops there and what did restore is left exactly as if it
   * had been opened by hand. Other independent branches still restore. There
   * is nothing here that can tell "excluded" apart from "never existed" —
   * both fail the same way, which is the same rule the server holds every
   * other path to. */
  async function restore() {
    const parsed = parseFragment();
    if (!parsed) return;
    const wanted = [...parsed.openPaths];
    if (parsed.viewPath) {
      const directory = parentOf(parsed.viewPath);
      if (directory) wanted.push(directory);
    }
    const ordered = [...withAncestors(wanted)].sort(
      (left, right) => left.split('/').length - right.split('/').length,
    );
    let complete = await restorePaths(ordered, openPath);
    if (complete && parsed.viewPath) {
      const entry = await findLoadedEntry(parsed.viewPath);
      complete = Boolean(entry);
      if (entry) await view(entry);
    }
    if (!complete) say(`${status.textContent} · the saved view could not be fully restored`);
  }

  function isImage(name) {
    const dot = name.lastIndexOf('.');
    return dot > 0 && IMAGE_EXTENSIONS.includes(name.slice(dot + 1).toLowerCase());
  }

  function viewerState(message, state = '') {
    const node = document.createElement('p');
    node.className = 'viewer-state';
    node.textContent = message;
    if (state) node.dataset.state = state;
    viewerBody.replaceChildren(node);
    return node;
  }

  async function view(entry) {
    const request = ++viewRequest;
    const opening = viewer.hidden;
    releaseViewBlob();
    // Before the address is written, so the entry underneath keeps the tree as
    // the person left it. Every call names the file, which is what a frame's
    // own head shows while this page is inside one.
    filePlace.enter();
    // What the head says while a file is open — this page's, whether the head
    // is the bar above or a frame's around it.
    pageHead.title(entry.name);
    viewing = entry;
    updateFragment();
    viewer.hidden = false;
    document.body.dataset.viewing = 'true';
    if (opening) viewerClose.focus({preventScroll: true});
    viewerTitle.textContent = entry.name;
    // The path, because in a tree a name alone does not say which of four
    // `mod.rs` a person is looking at.
    viewerMeta.textContent = entry.path;
    const loading = viewerState('Loading…', 'loading');

    if (isImage(entry.name)) {
      let body;
      try {
        body = await ask('read_bytes', {path: entry.path, offset_bytes: 0});
      } catch (error) {
        if (request !== viewRequest) return;
        viewerMeta.textContent = `${entry.path} · ${error.message}`;
        viewerState('This image could not be loaded.', 'error');
        return;
      }
      if (request !== viewRequest) {
        sessionRuntime.releaseBlob(body.blob);
        return;
      }
      viewBlob = body.blob;
      const image = document.createElement('img');
      image.className = 'preview';
      image.alt = entry.name;
      image.decoding = 'async';
      image.hidden = true;
      image.addEventListener('load', () => {
        if (request !== viewRequest) return;
        loading.remove();
        image.hidden = false;
      }, {once: true});
      image.addEventListener('error', () => {
        if (request !== viewRequest) return;
        releaseViewBlob();
        image.remove();
        viewerState('This image could not be loaded.', 'error');
      }, {once: true});
      // AFUI validates the opaque reference, serves it on this session's
      // origin, and applies the Provider's media allowlist plus `nosniff`.
      image.src = sessionRuntime.blobUrl(body.blob);
      viewerBody.append(image);
      viewerMeta.textContent = `${entry.path} · ${sizeOf(entry)}`;
      return;
    }

    let body;
    let text;
    try {
      body = await ask('read_text', {path: entry.path, offset_bytes: 0});
      const response = await sessionRuntime.fetchBlob(body.blob);
      text = await response.text();
    } catch (error) {
      if (body && body.blob) sessionRuntime.releaseBlob(body.blob);
      if (request !== viewRequest) return;
      viewerMeta.textContent =
        `${entry.path} · ${error.code === 'not_text' ? 'not text' : error.message}`;
      viewerState(
        error.code === 'not_text' ? 'This file is not text.' : 'This file could not be read.',
        'error',
      );
      return;
    }
    sessionRuntime.releaseBlob(body.blob);
    if (request !== viewRequest) return;
    const pre = document.createElement('pre');
    pre.className = 'source';
    // The whole point, in one line: a file is text on this page, whatever it
    // claims to be. There is no branch here that renders anything.
    pre.textContent = text;
    viewerBody.replaceChildren(pre);
    viewerMeta.textContent = body.file.truncated
      ? `${entry.path} · first ${body.file.byte_length} of ${body.file.total_bytes} bytes`
      : `${entry.path} · ${body.file.total_bytes} bytes`;
  }

  /* The root is filled the same way every other directory is, so it gets the
   * same paging control and there is one code path to be wrong in. */
  async function start() {
    say('loading');
    open.set('', {container: tree, depth: 0});
    const body = await fill(tree, '', 0, null);
    if (!body) {
      say('not answering');
      return;
    }
    await declareInterest();
    rootName.textContent = body.root.name;
    emptyState.hidden = tree.childElementCount > 0;
    say(`${body.listing.entry_count} at the root`);
    // Only after the root itself is on screen: everything `restore` opens is
    // found by walking down from here, never fetched by a path alone.
    await restore();
  }

  function applyRuntimeState(state) {
    if (!state) return;
    watchState = state.type;
    if (state.type === 'watch_unavailable') {
      say('not live');
      return;
    }
    if (state.type !== 'watching' || !started) return;
    const fullResync = resyncRequired || state.resync_required;
    const changed = Array.isArray(state.changed_paths) ? state.changed_paths : [];
    const paths = fullResync
      ? [...open.keys()]
      : [...open.keys()].filter(path =>
          changed.some(directory => atOrUnder(path, directory))
        );
    resyncRequired = false;
    const updates = paths.map(path => refresh(path));
    Promise.allSettled(updates).then(declareInterest);
    if (
      viewing &&
      (fullResync || changed.some(directory => atOrUnder(parentOf(viewing.path), directory)))
    ) {
      view(viewing);
    }
  }

  viewerClose.addEventListener('click', () => filePlace.leave());

  function boot() {
    const showConnection = afui.connection(status);
    sessionRuntime = afui.connect({
      onState: applyRuntimeState,
      onConnectionState: state => {
        /* One line for both kinds of message, so it takes AFUI's mark and
         * keeps its own wording: "not live" here also covers a workspace
         * nothing is watching, which is not a connection fact at all. */
        connection = state;
        if (state !== 'live') resyncRequired = true;
        showConnection(state);
        if (state === 'live') {
          say(watchState === 'watch_unavailable' ? 'not live' : 'live');
        } else if (state === 'reconnecting' || state === 'closed') {
          say('not live');
        }
      },
    });
    start().then(() => {
      started = true;
      if (sessionRuntime.state === 'live') {
        say(watchState === 'watch_unavailable' ? 'not live' : 'live');
      }
    });
  }

  boot();
})();
