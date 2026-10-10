import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../src/api/ui/app.js', import.meta.url), 'utf8');
const testSource = source.replace(
  'boot();',
  `globalThis.__affilesTest = {
    withAncestors,
    restorePaths,
    view,
    say,
    applyRuntimeState,
    start: () => { started = true; },
    open,
    setRuntime: runtime => { sessionRuntime = runtime; },
    isOpen: () => !viewer.hidden,
    viewedPath: () => (viewing ? viewing.path : null),
  };`,
);
assert.notEqual(testSource, source, 'the test hook must replace the one boot call');

/* The page's own two dependencies, stubbed no further than it reaches.
 *
 * Enough of a DOM to let a row be opened and closed, and a real history model —
 * a stack, a cursor, and a `popstate` on every move — because what is being
 * checked here is exactly what the browser does with the entries this page
 * pushes, and a history that never fires the event proves nothing. */
function stubElement() {
  const listeners = {};
  return {
    listeners,
    hidden: false,
    textContent: '',
    className: '',
    title: '',
    dataset: {},
    style: {},
    children: [],
    parentNode: null,
    addEventListener(type, handler) { listeners[type] = handler; },
    append(...children) {
      for (const child of children) {
        child.remove();
        child.parentNode = this;
        this.children.push(child);
      }
    },
    replaceChildren(...children) {
      for (const child of this.children) child.parentNode = null;
      this.children = [];
      this.append(...children);
    },
    remove() {
      if (!this.parentNode) return;
      this.parentNode.children = this.parentNode.children.filter(child => child !== this);
      this.parentNode = null;
    },
    focus() {},
    setAttribute() {},
    getAttribute() { return null; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
  };
}

function load() {
  const elements = new Map();
  const location = {pathname: '/', search: '', hash: ''};
  Object.defineProperty(location, 'href', {
    get: () => `${location.pathname}${location.search}${location.hash}`,
  });

  const window = {listeners: {}, addEventListener(type, handler) { this.listeners[type] = handler; }};
  const stack = ['/'];
  let cursor = 0;
  const apply = url => {
    const cut = url.indexOf('#');
    location.hash = cut === -1 ? '' : url.slice(cut);
  };
  const history = {
    pushed: 0,
    /** Set when a back gesture had nothing of this page's left to undo. */
    leftThePage: false,
    pushState(_state, _title, url) {
      stack.splice(cursor + 1);
      stack.push(url);
      cursor += 1;
      history.pushed += 1;
      apply(url);
    },
    replaceState(_state, _title, url) {
      stack[cursor] = url;
      apply(url);
    },
    back() {
      if (cursor === 0) {
        history.leftThePage = true;
        return;
      }
      cursor -= 1;
      apply(stack[cursor]);
      window.listeners.popstate();
    },
    forward() {
      if (cursor + 1 >= stack.length) return;
      cursor += 1;
      apply(stack[cursor]);
      window.listeners.popstate();
    },
  };

  // The viewer carries `hidden` in the markup, so it starts closed here too —
  // otherwise every open below is a re-open and pushes nothing.
  const viewer = stubElement();
  viewer.hidden = true;
  elements.set('viewer', viewer);

  /* AFUI's place primitive, recorded rather than reimplemented. What a place
   * does with a history entry is AFUI's to be right about and AFUI's to test;
   * what this page owes it is the four answers below, and getting one of those
   * wrong is a file that cannot be closed or an address that names one that is
   * not open. */
  const place = {options: null, entered: 0, left: 0};
  const head = {options: null, titles: [], statuses: []};
  const afui = {
    place(options) {
      place.options = options;
      return {
        enter: () => {
          place.entered += 1;
        },
        leave: () => {
          place.left += 1;
        },
      };
    },
    frame(options) {
      head.options = options;
      return {
        title: text => head.titles.push(text),
        status: (text, state) => head.statuses.push([text, state]),
        head: false,
      };
    },
  };

  const context = {
    afui,
    document: {
      body: stubElement(),
      listeners: {},
      addEventListener(type, handler) { this.listeners[type] = handler; },
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, stubElement());
        return elements.get(id);
      },
      createElement: () => stubElement(),
    },
    location,
    history,
    window,
    URLSearchParams,
    HTMLElement: class {},
  };
  vm.createContext(context);
  vm.runInContext(testSource, context, {filename: 'app.js'});
  return {
    ...context.__affilesTest,
    history,
    location,
    elements,
    place,
    head,
    body: context.document.body,
  };
}

/* A root directory with two files already listed in it, because everything the
 * page views it read off a row it had already been given. */
function listRoot(page, names) {
  const container = stubElement();
  container.querySelectorAll = () => names.map(name => {
    const row = stubElement();
    row.textContent = name;
    const item = stubElement();
    item.dataset.path = name;
    item.dataset.kind = 'file';
    item.querySelector = () => row;
    return item;
  });
  page.open.set('', {container, depth: 0});
}

const settle = () => new Promise(resolve => setTimeout(resolve, 0));

const {withAncestors, restorePaths} = load();

assert.deepEqual(
  [...withAncestors(['/secret', 'safe//child', 'safe/../child', 'safe/./child', 'good/deep'])],
  ['good', 'good/deep'],
  'malformed paths must be ignored, not normalised into valid root-relative paths',
);

const visited = [];
const complete = await restorePaths(['missing/branch', 'valid', 'valid/child'], async path => {
  visited.push(path);
  return path !== 'missing/branch';
});
assert.equal(complete, false);
assert.deepEqual(
  visited,
  ['missing/branch', 'valid', 'valid/child'],
  'one stale branch must not prevent an independent valid branch from restoring',
);

assert.equal(await restorePaths(['valid'], async () => true), true);
assert.match(source, /viewerState\('Loading…', 'loading'\)/);
assert.match(source, /This image could not be loaded\./);
assert.match(source, /if \(request !== viewRequest\) return;/);

/* What this page owes the place it declares.
 *
 * The file is a place: on the width where it covers the tree completely, the
 * gesture a person reaches for is the one that leaves a screen, and AFUI is
 * what makes the four ways out agree. This page's half is telling it which
 * file the address names, showing one it did not open by hand, taking one
 * down, and standing aside when the window frame around it already draws the
 * way back. */
const page = load();
listRoot(page, ['README.md', 'notes.txt']);
const {options} = page.place;

await page.view({path: 'README.md', name: 'README.md'});
assert.equal(page.isOpen(), true);
assert.equal(page.place.entered, 1, 'opening a file enters the place');
assert.deepEqual(
  page.head.titles,
  ['README.md'],
  'and names it in the head, which is the frame\'s when there is one and this page\'s bar when there is not',
);
assert.match(page.location.hash, /view=README.md/);
assert.equal(
  options.at(),
  'README.md',
  'the place asks what the address names, and this page answers from the address alone',
);

await page.view({path: 'notes.txt', name: 'notes.txt'});
assert.deepEqual(page.head.titles, ['README.md', 'notes.txt']);
assert.equal(options.at(), 'notes.txt');

// Arriving somewhere this page did not open by hand — a person going forward,
// or an address they were sent.
await options.show('README.md');
await settle();
assert.equal(page.viewedPath(), 'README.md');
const shownAgain = page.head.titles.length;
await options.show('README.md');
await settle();
assert.equal(
  page.head.titles.length,
  shownAgain,
  'being told to show the file already open must not re-read it',
);

options.hide();
assert.equal(page.isOpen(), false, 'the place takes the file down through this page, once');
assert.equal(
  page.head.titles.at(-1),
  null,
  'and the head goes back to saying whatever the session itself is on',
);
assert.doesNotMatch(page.location.hash, /view=/, 'a closed file stops being in the address');
assert.equal(options.at(), null);

// The one control this page draws for itself, and the one it stands aside for.
const closeControl = page.elements.get('viewer-close');
closeControl.listeners.click();
assert.equal(page.place.left, 1, 'this page asks to leave; it never closes the place behind its back');
// The head this page hands over, and the one it keeps.
page.head.options.onHead(true);
assert.equal(
  page.body.dataset.frameHead,
  'true',
  'a frame with a head of its own leaves this page drawing none: its three parts are already up there',
);
page.head.options.onHead(false);
assert.equal(page.body.dataset.frameHead, 'false');
page.say('16 at the root');
assert.equal(page.elements.get('status').textContent, '16 at the root');
assert.deepEqual(
  page.head.statuses.at(-1),
  ['16 at the root', 'connecting'],
  'the one part of the head a frame cannot know goes up as this page says it, marked with AFUI\'s own word',
);
assert.doesNotMatch(
  JSON.stringify(page.head.titles.concat(page.head.statuses.map(([text]) => text))),
  /Agent-First Files/,
  'identity is the listener\'s word; this page never sends its own name to a head it does not own',
);

options.onFrame({navigation: true});
assert.equal(
  page.body.dataset.frameNavigation,
  'true',
  'a frame that draws the way back is a fact about the page, which the stylesheet answers by width',
);
options.onFrame({navigation: false});
assert.equal(
  page.body.dataset.frameNavigation,
  'false',
  'delivered as its own window there is no head but this one',
);

/* Execute the image branch and its real handlers. The stub records a decode
 * attempt and lets each load/error arrive at the same boundary as a browser;
 * it does not pretend to decode image bytes. */
function imageReply(name, truncated) {
  return {
    type: 'read_bytes',
    byte_offset: 0,
    total_bytes: 2 * 1024 * 1024,
    truncated,
    blob: {
      blob_url: `__afui/blobs/${name}`,
      media_type: 'image/png',
      size_bytes: truncated ? 1024 * 1024 : 2 * 1024 * 1024,
    },
  };
}

function imagePage(read) {
  const page = load();
  const released = [];
  const attempts = [];
  page.setRuntime({
    call(action) {
      assert.equal(action.type, 'read_bytes');
      assert.equal(action.offset_bytes, 0);
      return read(action);
    },
    blobUrl(blob) {
      attempts.push({blob, metadata: page.elements.get('viewer-meta').textContent});
      return blob.blob_url;
    },
    releaseBlob(blob) { released.push(blob); },
  });
  return {page, released, attempts, body: page.elements.get('viewer-body')};
}

const imageEntry = name => ({path: name, name, kind: 'file', size_bytes: 2 * 1024 * 1024});
const preview = body => body.children.find(child => child.className === 'preview');

{
  const reply = imageReply('partial-success', true);
  const {page, body, attempts, released} = imagePage(() => reply);
  await page.view(imageEntry('large.png'));
  const image = preview(body);
  assert.ok(image, 'truncation must still attempt an image preview');
  assert.equal(image.src, reply.blob.blob_url);
  assert.equal(image.hidden, true);
  assert.match(attempts[0].metadata, /preview incomplete/, 'the limit is visible before decoding');
  image.listeners.load();
  assert.equal(image.hidden, false, 'a partial image that decodes is still shown');
  assert.deepEqual(body.children, [image], 'a successful load clears only the loading message');
  assert.match(page.elements.get('viewer-meta').textContent, /preview incomplete/);
  assert.deepEqual(released, [], 'the displayed image keeps its blob until the viewer closes');
  page.place.options.hide();
  assert.deepEqual(released, [reply.blob]);
  assert.deepEqual(body.children, []);
}

{
  const reply = imageReply('partial-failure', true);
  const {page, body, attempts, released} = imagePage(() => reply);
  await page.view(imageEntry('large.png'));
  assert.equal(attempts.length, 1, 'a partial image is tried rather than refused');
  preview(body).listeners.error();
  assert.equal(preview(body), undefined);
  assert.match(body.children[0].textContent, /preview is incomplete/);
  assert.doesNotMatch(body.children[0].textContent, /could not be loaded/);
  assert.match(page.elements.get('viewer-meta').textContent, /preview incomplete/);
  assert.deepEqual(released, [reply.blob], 'a decode failure releases its body');
  page.place.options.hide();
  assert.deepEqual(released, [reply.blob], 'closing the failed preview does not release twice');
}

{
  const reply = imageReply('ordinary-failure', false);
  const {page, body, released} = imagePage(() => reply);
  await page.view(imageEntry('broken.png'));
  preview(body).listeners.error();
  assert.equal(body.children[0].textContent, 'This image could not be loaded.');
  assert.doesNotMatch(page.elements.get('viewer-meta').textContent, /preview incomplete/);
  assert.deepEqual(released, [reply.blob]);
  page.place.options.hide();
  assert.deepEqual(released, [reply.blob]);
}

{
  let finishOld;
  const waiting = new Promise(resolve => { finishOld = resolve; });
  const oldReply = imageReply('late-partial', true);
  const currentReply = imageReply('current', false);
  const {page, body, attempts, released} = imagePage(action =>
    action.path === 'old.png' ? waiting : currentReply,
  );
  const oldView = page.view(imageEntry('old.png'));
  await page.view(imageEntry('current.png'));
  const currentImage = preview(body);
  const currentMetadata = page.elements.get('viewer-meta').textContent;
  finishOld(oldReply);
  await oldView;
  assert.deepEqual(released, [oldReply.blob], 'a stale read reply releases its unused body');
  assert.equal(attempts.length, 1, 'a stale reply must never start decoding');
  assert.equal(preview(body), currentImage);
  assert.equal(page.elements.get('viewer-meta').textContent, currentMetadata);
  assert.doesNotMatch(currentMetadata, /preview incomplete/);
  currentImage.listeners.load();
  page.place.options.hide();
  assert.deepEqual(released, [oldReply.blob, currentReply.blob]);
}

{
  const oldReply = imageReply('old-partial', true);
  const currentReply = imageReply('new-complete', false);
  const {page, body, released} = imagePage(action =>
    action.path === 'old.png' ? oldReply : currentReply,
  );
  await page.view(imageEntry('old.png'));
  const oldImage = preview(body);
  await page.view(imageEntry('current.png'));
  const currentImage = preview(body);
  oldImage.listeners.load();
  oldImage.listeners.error();
  assert.equal(preview(body), currentImage, 'late image callbacks leave the current preview intact');
  assert.equal(currentImage.hidden, true, 'only this image\'s own load may reveal it');
  assert.doesNotMatch(page.elements.get('viewer-meta').textContent, /preview incomplete/);
  assert.deepEqual(released, [oldReply.blob], 'late callbacks must not release the current image');
  currentImage.listeners.load();
  page.place.options.hide();
  assert.deepEqual(released, [oldReply.blob, currentReply.blob]);
}


{
  const page = load();
  const body = page.elements.get('viewer-body');
  let finishRead;
  let readingStarted;
  const readStarted = new Promise(resolve => { readingStarted = resolve; });
  let pending = false;
  const entry = {path: 'notes.txt', name: 'notes.txt', kind: 'file', size_bytes: 10};
  page.setRuntime({
    call(action) {
      assert.equal(action.type, 'read_text');
      return {type: 'read_text', blob: {blob_url: 'text'}, file: {total_bytes: 10, truncated: false}};
    },
    fetchBlob() {
      return {text: () => pending ? new Promise(resolve => { finishRead = resolve; readingStarted(); }) : Promise.resolve('old text')};
    },
    releaseBlob() {},
  });
  const first = page.view(entry);
  assert.equal(body.children[0].dataset.state, 'loading');
  await first;
  const old = body.children[0];
  pending = true;
  page.start();
  const refreshed = page.applyRuntimeState({type: 'watching', changed_paths: ['']});
  await readStarted;
  assert.equal(body.children[0], old, 'unrelated root changes retain displayed text during refresh');
  assert.equal(body.children[0].textContent, 'old text');
  assert.ok(body.children.every(child => child.dataset.state !== 'loading'));
  finishRead('new text');
  await refreshed;
  assert.equal(body.children[0].textContent, 'new text');
}

{
  const oldReply = imageReply('refresh-old', false);
  const newReply = imageReply('refresh-new', false);
  let reply = oldReply;
  const {page, body, released} = imagePage(() => reply);
  await page.view(imageEntry('same.png'));
  const oldImage = preview(body);
  oldImage.listeners.load();
  reply = newReply;
  await page.view(imageEntry('same.png'));
  const newImage = body.children.find(child => child !== oldImage);
  assert.equal(oldImage.parentNode, body, 'old image remains displayed while replacement decodes');
  assert.deepEqual(released, []);
  newImage.listeners.load();
  assert.deepEqual(body.children, [newImage]);
  assert.deepEqual(released, [oldReply.blob]);
  page.place.options.hide();
  assert.deepEqual(released, [oldReply.blob, newReply.blob]);
}
