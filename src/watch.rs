//! Telling a viewer that what it is showing has stopped being true.
//!
//! # Watch exactly what is open
//!
//! The obvious implementation watches the root recursively, and it is the same
//! mistake as reading the tree up front — worse, because it is paid
//! continuously rather than once. A recursive watch over a repository registers
//! one inotify watch per directory on Linux, which a `node_modules` exhausts
//! outright, and it makes this process do work for parts of the tree nobody has
//! looked at.
//!
//! So the rule is the same rule the tree already follows: **a directory is
//! watched exactly while somebody has it open.** The viewer says which
//! directories those are, the set is replaced wholesale each time it changes,
//! and a collapsed directory stops costing anything the moment it is collapsed.
//! Nothing is recursive; a change two levels down in an unopened subtree is not
//! this process's business.
//!
//! # An event is a fact, never content
//!
//! [`WatchEvent::Changed`] carries the root-relative directories affected by
//! one coalescing window and nothing else — not what changed, not the new
//! listing, not a size. A viewer that cares reads those directories again
//! through the ordinary route, which means
//! there is one code path that produces a listing and one set of rules deciding
//! what may appear in it. An event carrying entries would be a second one,
//! quietly exempt from paging and from exclusion.
//!
//! # An excluded change is not an event
//!
//! If the entry that changed is excluded, nothing is emitted at all — not even
//! "its parent changed". A person who excluded `secrets/**` and can still watch
//! events arrive whenever those files are written has been told they exist and
//! when they are being used. When something else in that directory changes, it
//! produces its own event.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use notify::{RecommendedWatcher, RecursiveMode, Watcher};

use crate::{FileRoot, RelPath, Result};

/// The most directories one viewer may have registered at once.
///
/// A page shows the directories a person has expanded, and a person does not
/// expand thousands. The ceiling exists for the caller who is not a person:
/// each registration is a kernel resource drawn from a per-user pool shared
/// with everything else running, and the limit is fixed here rather than
/// configurable so no deployment can be talked into removing it.
pub const MAX_WATCHED_DIRECTORIES: usize = 512;

/// How long changes are gathered before the viewer is told.
///
/// A build writes thousands of files; a viewer does not need to hear about each
/// one, and re-reading a directory per write would turn one `cargo build` into
/// a request storm. Long enough to collapse a burst, short enough that a person
/// saving a file sees it land.
const COALESCE: Duration = Duration::from_millis(250);

/// What happened, at the only granularity a listing cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchEvent {
    /// These directories' listings may have changed. Each path appears once,
    /// in byte order, and the whole coalescing window is one event.
    Changed { paths: Vec<String> },
}

/// A live watch over the directories somebody currently has open.
pub struct RootWatcher {
    watcher: Mutex<RecommendedWatcher>,
    /// The real paths currently registered, so a replacement can add and remove
    /// rather than tear the whole set down and rebuild it — rebuilding would
    /// drop events for directories that stayed open throughout.
    watched: Mutex<HashSet<PathBuf>>,
}

impl FileRoot {
    /// Start watching, with nothing watched yet.
    ///
    /// The registration handle and the stream come back separately because they
    /// go to different places: one is held by whatever knows what is on screen,
    /// the other is drained by whatever fans events out to readers.
    ///
    /// Failure here is not fatal to browsing and callers are expected to treat
    /// it that way: a projection with no watcher is a viewer that does not
    /// update by itself, which is worse than one that does and better than no
    /// viewer at all.
    pub fn watch(&self) -> Result<(RootWatcher, Receiver<WatchEvent>)> {
        let (raw_sender, raw_receiver) = channel::<PathBuf>();
        let watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
            let Ok(event) = event else {
                return;
            };
            for path in event.paths {
                // A closed channel means the watcher outlived its reader, which
                // is a shutdown rather than something to report.
                if raw_sender.send(path).is_err() {
                    return;
                }
            }
        })
        .map_err(watch_error)?;

        let (sender, events) = channel();
        let translator = Translator {
            root: self.root_path().to_path_buf(),
            exclude: self.exclude_patterns().to_vec(),
        };
        spawn_coalescer(raw_receiver, sender, translator);

        Ok((
            RootWatcher {
                watcher: Mutex::new(watcher),
                watched: Mutex::new(HashSet::new()),
            },
            events,
        ))
    }
}

impl RootWatcher {
    /// Replace the watched set with exactly these directories, or change
    /// nothing and say so.
    ///
    /// Wholesale rather than incremental, because the viewer already knows the
    /// whole answer — what it has open — and an add/remove protocol would let
    /// the two drift apart with nothing to notice.
    ///
    /// Every failure here used to be dropped — an unresolvable path, a refused
    /// registration, a failed removal — and the new set was then installed and
    /// success returned. The page reads that as live and waits for events that
    /// cannot arrive, which is the one answer worse than an error: a viewer
    /// told the watch failed re-reads, and a viewer told nothing shows a
    /// directory that quietly stopped being true.
    pub fn set_paths(&self, root: &FileRoot, paths: &[RelPath]) -> Result<()> {
        // Registrations cost a kernel resource — one inotify watch each on
        // Linux, against a per-user ceiling shared with every other program.
        // The bound is checked before any of them is taken, and it is not
        // something a request can raise.
        if paths.len() > MAX_WATCHED_DIRECTORIES {
            return Err(crate::FilesError::TooManyWatches {
                requested: paths.len(),
                limit: MAX_WATCHED_DIRECTORIES,
            });
        }
        let mut wanted = HashSet::new();
        for path in paths {
            // Through the same resolution every read goes through, so a caller
            // cannot register a watch on something it could not have listed —
            // and one path it cannot fails the whole request, rather than
            // leaving the caller to guess which of its directories are live.
            wanted.insert(root.resolve_directory(path)?);
        }

        let mut watcher = self.watcher.lock().map_err(|_| poisoned())?;
        let mut watched = self.watched.lock().map_err(|_| poisoned())?;

        // Registrations first, and undone as a group if any of them is refused,
        // so the authoritative set is never a set this process is not actually
        // watching.
        let mut added: Vec<PathBuf> = Vec::new();
        for path in wanted.difference(&watched) {
            // Never recursive. A subtree nobody opened is a subtree nobody is
            // shown, so watching it would be work with no reader.
            if watcher.watch(path, RecursiveMode::NonRecursive).is_err() {
                for rollback in &added {
                    let _ignored = watcher.unwatch(rollback);
                }
                return Err(crate::FilesError::WatchRegistrationFailed);
            }
            added.push(path.clone());
        }

        // Removals last, and a removal that fails keeps its path in the set.
        // Still being watched costs an event the viewer will ignore; claiming
        // it is not watched when it is would make the next `set_paths` skip a
        // registration it still needs.
        let mut next = wanted.clone();
        for gone in watched.difference(&wanted) {
            if watcher.unwatch(gone).is_err() {
                next.insert(gone.clone());
            }
        }
        *watched = next;
        Ok(())
    }
}

/// Turning a platform path into the one thing a listing is keyed by.
struct Translator {
    root: PathBuf,
    exclude: Vec<String>,
}

impl Translator {
    /// The directory whose listing this change affects, if any.
    ///
    /// The parent, because a listing shows entries and it is an entry that
    /// changed. `None` when the change is outside the root, or when what
    /// changed is excluded — see the module documentation for why an excluded
    /// write must not produce even a parent event.
    fn directory_of(&self, changed: &Path) -> Option<String> {
        let relative = changed.strip_prefix(&self.root).ok()?;
        let relative = relative.to_str()?;
        if self.excluded(relative) {
            return None;
        }
        let parent = match relative.rsplit_once('/') {
            Some((parent, _)) => parent,
            None => "",
        };
        if self.excluded(parent) {
            return None;
        }
        Some(parent.to_owned())
    }

    fn excluded(&self, candidate: &str) -> bool {
        !candidate.is_empty()
            && self
                .exclude
                .iter()
                .any(|pattern| crate::pattern_excludes(pattern, candidate))
    }
}

/// Gather a burst, then say all affected directories once.
fn spawn_coalescer(raw: Receiver<PathBuf>, sender: Sender<WatchEvent>, translator: Translator) {
    std::thread::spawn(move || {
        let mut pending: BTreeSet<String> = BTreeSet::new();
        loop {
            // Block until something happens, then keep taking whatever arrives
            // inside the window before saying anything.
            let first = match raw.recv() {
                Ok(path) => path,
                Err(_) => return,
            };
            if let Some(directory) = translator.directory_of(&first) {
                pending.insert(directory);
            }
            let deadline = std::time::Instant::now() + COALESCE;
            while let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) {
                match raw.recv_timeout(remaining) {
                    Ok(path) => {
                        if let Some(directory) = translator.directory_of(&path) {
                            pending.insert(directory);
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                }
            }
            if !pending.is_empty() {
                let paths = std::mem::take(&mut pending).into_iter().collect();
                if sender.send(WatchEvent::Changed { paths }).is_err() {
                    return;
                }
            }
        }
    });
}

fn watch_error(error: notify::Error) -> crate::FilesError {
    crate::FilesError::Io(std::io::Error::other(error.to_string()))
}

fn poisoned() -> crate::FilesError {
    crate::FilesError::Io(std::io::Error::other("the watch registry is poisoned"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::FileRootConfig;

    /// Give a platform watcher time to register and then to report. Generous,
    /// because a slow CI box failing this test would say nothing true.
    fn wait_for(events: &Receiver<WatchEvent>, wanted: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match events.recv_timeout(Duration::from_millis(200)) {
                Ok(WatchEvent::Changed { paths }) if paths.iter().any(|path| path == wanted) => {
                    return true;
                }
                Ok(_) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => return false,
            }
        }
        false
    }

    fn quiet_for(events: &Receiver<WatchEvent>, window: Duration) -> bool {
        matches!(
            events.recv_timeout(window),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        )
    }

    #[test]
    fn one_burst_is_one_sorted_event_even_when_several_directories_change() {
        let base = tempfile::tempdir().expect("temp");
        let (raw_sender, raw_receiver) = channel();
        let (event_sender, events) = channel();
        spawn_coalescer(
            raw_receiver,
            event_sender,
            Translator {
                root: base.path().to_path_buf(),
                exclude: Vec::new(),
            },
        );

        raw_sender
            .send(base.path().join("z/file"))
            .expect("first change");
        raw_sender
            .send(base.path().join("a/file"))
            .expect("second change");
        raw_sender
            .send(base.path().join("z/other"))
            .expect("duplicate directory");

        let event = events
            .recv_timeout(Duration::from_secs(2))
            .expect("coalesced event");
        assert_eq!(
            event,
            WatchEvent::Changed {
                paths: vec!["a".to_owned(), "z".to_owned()]
            }
        );
        assert!(quiet_for(&events, Duration::from_millis(400)));
    }

    #[test]
    fn a_write_in_a_watched_directory_names_that_directory() {
        let base = tempfile::tempdir().expect("temp");
        fs::create_dir_all(base.path().join("src")).expect("dir");
        let root = FileRoot::open(FileRootConfig::new(base.path())).expect("root");
        let (watcher, events) = root.watch().expect("watch");
        watcher
            .set_paths(&root, &[RelPath::parse("src").expect("path")])
            .expect("set paths");
        std::thread::sleep(Duration::from_millis(300));

        fs::write(base.path().join("src/new.rs"), "fn main() {}\n").expect("write");
        assert!(
            wait_for(&events, "src"),
            "a change to an entry must name the directory whose listing it changes"
        );
    }

    /// The whole point of watching only what is open: an unopened subtree costs
    /// nothing, produces nothing, and is nobody's business.
    #[test]
    fn a_change_in_a_directory_nobody_opened_is_not_reported() {
        let base = tempfile::tempdir().expect("temp");
        fs::create_dir_all(base.path().join("closed")).expect("dir");
        let root = FileRoot::open(FileRootConfig::new(base.path())).expect("root");
        let (watcher, events) = root.watch().expect("watch");
        watcher
            .set_paths(&root, &[RelPath::root()])
            .expect("set paths");
        std::thread::sleep(Duration::from_millis(300));

        fs::write(base.path().join("closed/deep.txt"), "deep\n").expect("write");
        assert!(
            quiet_for(&events, Duration::from_secs(1)),
            "only directories somebody has open are watched"
        );
    }

    /// An excluded write must not arrive even as "its parent changed": that is
    /// a timing channel telling a person the file exists and is in use.
    #[test]
    fn an_excluded_write_produces_no_event_at_all() {
        let base = tempfile::tempdir().expect("temp");
        let root =
            FileRoot::open(FileRootConfig::new(base.path()).with_exclude([".env".to_owned()]))
                .expect("root");
        let (watcher, events) = root.watch().expect("watch");
        watcher
            .set_paths(&root, &[RelPath::root()])
            .expect("set paths");
        std::thread::sleep(Duration::from_millis(300));

        fs::write(base.path().join(".env"), "TOKEN=1\n").expect("write");
        assert!(
            quiet_for(&events, Duration::from_secs(1)),
            "an excluded entry must not be observable through the change stream"
        );

        // And the stream is still live for something that is not excluded.
        fs::write(base.path().join("README.md"), "# hello\n").expect("write");
        assert!(wait_for(&events, ""), "the root is still watched");
    }

    /// Collapsing a directory stops it costing anything.
    #[test]
    fn replacing_the_watched_set_stops_the_directories_left_out_of_it() {
        let base = tempfile::tempdir().expect("temp");
        fs::create_dir_all(base.path().join("a")).expect("dir");
        fs::create_dir_all(base.path().join("b")).expect("dir");
        let root = FileRoot::open(FileRootConfig::new(base.path())).expect("root");
        let (watcher, events) = root.watch().expect("watch");
        let a = RelPath::parse("a").expect("path");
        let b = RelPath::parse("b").expect("path");
        watcher
            .set_paths(&root, &[a.clone(), b.clone()])
            .expect("set paths");
        std::thread::sleep(Duration::from_millis(300));

        watcher.set_paths(&root, &[b]).expect("set paths");
        std::thread::sleep(Duration::from_millis(300));
        fs::write(base.path().join("a/gone.txt"), "x").expect("write");
        assert!(
            quiet_for(&events, Duration::from_secs(1)),
            "a directory left out of the set is no longer watched"
        );

        fs::write(base.path().join("b/here.txt"), "x").expect("write");
        assert!(wait_for(&events, "b"), "the directory still in the set is");
        let _kept = a;
    }

    /// A watch cannot be registered on something the caller could not have
    /// listed, because it goes through the same resolution a read does.
    ///
    /// Unix-only for the reason the projection's own link tests are: the only
    /// way to try this is a symlink, and creating one on Windows needs a
    /// privilege the host may not grant. The Windows ways out of a directory —
    /// junctions, `\\?\` paths, drive-relative paths — are not covered here
    /// either, for watches any more than for reads.
    #[cfg(unix)]
    #[test]
    fn a_path_outside_the_root_cannot_be_watched() {
        let base = tempfile::tempdir().expect("temp");
        fs::create_dir_all(base.path().join("root")).expect("dir");
        fs::create_dir_all(base.path().join("outside")).expect("dir");
        let root = FileRoot::open(FileRootConfig::new(base.path().join("root"))).expect("root");
        let (watcher, events) = root.watch().expect("watch");
        // `..` never parses, so the only way to try is a link, and resolution
        // refuses it the same way a read would.
        std::os::unix::fs::symlink(base.path().join("outside"), base.path().join("root/escape"))
            .expect("link");
        let refused = watcher.set_paths(&root, &[RelPath::parse("escape").expect("path")]);
        assert!(
            refused.is_err(),
            "a path that will not resolve fails the request rather than being dropped from it"
        );
        std::thread::sleep(Duration::from_millis(300));

        fs::write(base.path().join("outside/secret.txt"), "x").expect("write");
        assert!(
            quiet_for(&events, Duration::from_secs(1)),
            "resolution refuses a watch on a link out of the root"
        );
    }

    #[test]
    fn one_unwatchable_path_fails_the_whole_request() {
        let base = tempfile::tempdir().expect("temp");
        let root_path = base.path().join("root");
        fs::create_dir_all(root_path.join("open")).expect("dir");
        let root = FileRoot::open(FileRootConfig::new(&root_path)).expect("root");
        let (watcher, _events) = root.watch().expect("watch");

        watcher
            .set_paths(&root, &[RelPath::parse("open").expect("path")])
            .expect("a directory that exists is watchable");

        // One good path and one that cannot resolve. Registering the good one
        // and reporting success would leave the viewer believing both are live.
        let mixed = watcher.set_paths(
            &root,
            &[
                RelPath::parse("open").expect("path"),
                RelPath::parse("gone").expect("path"),
            ],
        );
        assert!(mixed.is_err(), "a partial watch must not report success");
    }

    #[test]
    fn more_directories_than_the_ceiling_are_refused_before_any_registration() {
        let base = tempfile::tempdir().expect("temp");
        let root_path = base.path().join("root");
        fs::create_dir_all(&root_path).expect("dir");
        let root = FileRoot::open(FileRootConfig::new(&root_path)).expect("root");
        let (watcher, _events) = root.watch().expect("watch");

        // Never created on disk: the ceiling is checked before anything is
        // resolved, so this costs one comparison rather than a kernel resource
        // per name.
        let paths: Vec<RelPath> = (0..=MAX_WATCHED_DIRECTORIES)
            .map(|index| RelPath::parse(&format!("d{index}")).expect("path"))
            .collect();

        assert!(matches!(
            watcher.set_paths(&root, &paths),
            Err(crate::FilesError::TooManyWatches { .. })
        ));
    }
}
