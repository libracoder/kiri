//! The Linux window: GTK 3 and the system's WebKitGTK (4.1), the same
//! WebKit the Mac uses. The page is unchanged: it posts to
//! `webkit.messageHandlers.kiri`, which WebKitGTK has too, and gets events
//! through `kiri.on(...)`.
//!
//! The window keeps the desktop's own title bar, as on Windows. Closing it
//! quits the window only: the engine is a system service and keeps running.

use std::cell::RefCell;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::io;
use std::sync::mpsc;

use gtk::gdk_pixbuf::{Pixbuf, PixbufLoader};
use gtk::glib;
use gtk::prelude::*;
use javascriptcore::ValueExt;
use webkit2gtk::{SettingsExt, UserContentInjectedFrames, UserContentManager, UserContentManagerExt, UserScript, UserScriptInjectionTime, WebView, WebViewExt};

use super::{Cmd, PAGE, engine, prefs};

thread_local! {
    /// The page and its window. Only ever touched on GTK's main thread.
    static WEBVIEW: RefCell<Option<WebView>> = const { RefCell::new(None) };
    static WINDOW: RefCell<Option<gtk::Window>> = const { RefCell::new(None) };
}

/// Before the page's own scripts: which system this is.
const SHIM: &str = r#"window.KIRI_OS = "linux";"#;

const ICON_PNG: &[u8] = include_bytes!("../../../../brand/icon/png/kiri-app-icon-512.png");

/// `autostart` starts the engine as soon as the page has loaded; `view` picks
/// the sidebar section to open on.
pub fn run(autostart: bool, view: Option<String>) -> io::Result<()> {
    // The desktop file's name, before GTK starts: on Wayland it's the window's
    // app id, which is how the dock finds Kiri's launcher and icon.
    glib::set_prgname(Some("kiri"));
    gtk::init().map_err(|e| io::Error::other(format!("no display to open the window on ({e})")))?;
    let (tx, rx) = mpsc::channel();
    let engine_tx = tx.clone();
    let engine = std::thread::Builder::new().name("kiri-engine".into()).spawn(move || engine(rx, engine_tx))?;

    let window = gtk::Window::new(gtk::WindowType::Toplevel);
    window.set_title(crate::flavor::APP.get());
    if let Some(icon) = icon() {
        window.set_icon(Some(&icon));
    }
    // 1280x800, never more than nine tenths of the screen, as on the Mac and Windows.
    let (mut w, mut h) = (1280, 800);
    if let Some(area) = gtk::gdk::Display::default().and_then(|d| d.primary_monitor().or_else(|| d.monitor(0))).map(|m| m.workarea()) {
        w = w.min(area.width() * 9 / 10);
        h = h.min(area.height() * 9 / 10);
    }
    window.set_default_size(w, h);
    window.set_size_request(760, 480);
    window.set_position(gtk::WindowPosition::Center);

    let content = UserContentManager::new();
    content.add_script(&UserScript::new(SHIM, UserContentInjectedFrames::TopFrame, UserScriptInjectionTime::Start, &[], &[]));
    content.register_script_message_handler("kiri");
    let page_tx = tx.clone();
    content.connect_script_message_received(Some("kiri"), move |_, message| {
        if let Some(text) = message.js_value().map(|v| v.to_str()) {
            super::handle(&text, &page_tx, autostart, view.as_deref());
        }
    });
    let webview = WebView::with_user_content_manager(&content);
    if let Some(settings) = WebViewExt::settings(&webview) {
        settings.set_enable_developer_extras(cfg!(debug_assertions));
        // Drawn on the CPU, not through OpenGL: a page of lists needs no GPU,
        // and WebKit's GL compositing redraws the whole window for every
        // animation, which cost 26% of a core idle where there is no GPU
        // (a VM; software GL), against under 1.5% without it.
        settings.set_hardware_acceleration_policy(webkit2gtk::HardwareAccelerationPolicy::Never);
        whole_frames(&settings);
        settings.set_enable_write_console_messages_to_stdout(cfg!(debug_assertions));
    }
    webview.load_html(&super::assemble::page(PAGE, super::prefs()["lang"].as_str()), None);
    window.add(&webview);
    // Before set_appearance, which gives it its background.
    WEBVIEW.with(|v| *v.borrow_mut() = Some(webview));

    set_appearance(prefs()["theme"].as_str().unwrap_or("system"));
    let quit_tx = tx;
    window.connect_delete_event(move |_, _| {
        let _ = quit_tx.send(Cmd::Quit);
        gtk::main_quit();
        glib::Propagation::Proceed
    });
    window.show_all();
    WINDOW.with(|v| *v.borrow_mut() = Some(window));
    gtk::main();
    let _ = engine.join();
    Ok(())
}

/// Turns off WebKit's `PropagateDamagingInformation`. With it on and no GPU
/// compositing (see `run`), WebKitGTK 2.52 and 2.54 hand GTK only each frame's
/// repainted rectangles, and GTK 3 clears the rest of the view to the
/// window's own background: hover a row and the main pane goes blank,
/// leaving only the strip and the status bar. An opaque view background
/// (`page_background`) did not stop it. With propagation off WebKit marks the
/// whole view as changed in every frame, which costs next to nothing here
/// since the CPU is already drawing the frame.
///
/// The feature API is WebKitGTK 2.42 and the bindings stop at 2.40, so it is
/// looked up at run time: on an older WebKit, or one without the feature,
/// this does nothing.
fn whole_frames(settings: &webkit2gtk::Settings) {
    let (Some(all), Some(len), Some(get), Some(id), Some(set), Some(unref)) = (
        sym(c"webkit_settings_get_all_features"),
        sym(c"webkit_feature_list_get_length"),
        sym(c"webkit_feature_list_get"),
        sym(c"webkit_feature_get_identifier"),
        sym(c"webkit_settings_set_feature_enabled"),
        sym(c"webkit_feature_list_unref"),
    ) else {
        return;
    };
    // SAFETY: the symbols have the signatures WebKitGTK 2.42 documents; the
    // list is ours until unref, and its features live as long as it does.
    unsafe {
        let api = FeatureApi {
            all: std::mem::transmute::<*mut c_void, AllFeatures>(all),
            len: std::mem::transmute::<*mut c_void, ListLen>(len),
            get: std::mem::transmute::<*mut c_void, ListGet>(get),
            id: std::mem::transmute::<*mut c_void, Identifier>(id),
            set: std::mem::transmute::<*mut c_void, SetEnabled>(set),
            unref: std::mem::transmute::<*mut c_void, Unref>(unref),
        };
        api.disable_damage_propagation(settings.as_ptr().cast());
    }
}

type AllFeatures = unsafe extern "C" fn() -> *mut c_void;
type ListLen = unsafe extern "C" fn(*mut c_void) -> usize;
type ListGet = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;
type Identifier = unsafe extern "C" fn(*mut c_void) -> *const c_char;
type SetEnabled = unsafe extern "C" fn(*mut c_void, *mut c_void, c_int);
type Unref = unsafe extern "C" fn(*mut c_void);

struct FeatureApi {
    all: AllFeatures,
    len: ListLen,
    get: ListGet,
    id: Identifier,
    set: SetEnabled,
    unref: Unref,
}

impl FeatureApi {
    /// # Safety
    /// `self` must hold functions matching WebKitGTK 2.42's `WebKitFeatureList`
    /// C ABI, and `settings` must be a valid `WebKitSettings *` for `self.set`.
    unsafe fn disable_damage_propagation(&self, settings: *mut c_void) {
        // SAFETY: caller guarantees the function pointers and settings pointer.
        unsafe {
            let list = (self.all)();
            if list.is_null() {
                return;
            }
            for i in 0..(self.len)(list) {
                let feature = (self.get)(list, i);
                if !feature.is_null() {
                    let name = (self.id)(feature);
                    if !name.is_null() && CStr::from_ptr(name) == c"PropagateDamagingInformation" {
                        (self.set)(settings, feature, 0);
                    }
                }
            }
            (self.unref)(list);
        }
    }
}

fn sym(name: &CStr) -> Option<*mut c_void> {
    // SAFETY: a lookup by name in the already-loaded process symbols.
    let p = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    (!p.is_null()).then_some(p)
}

fn icon() -> Option<Pixbuf> {
    let loader = PixbufLoader::new();
    loader.write(ICON_PNG).ok()?;
    loader.close().ok()?;
    loader.pixbuf()
}

/// Runs JavaScript in the page. Callable from any thread.
/// The language setting changed: the page redraws its own words, and the
/// GTK window draws none of its own.
pub(super) fn relang() {}

pub(super) fn eval(js: String) {
    glib::MainContext::default().invoke(move || {
        WEBVIEW.with(|v| {
            if let Some(webview) = v.borrow().as_ref() {
                webview.evaluate_javascript(&js, None, None, None::<&gtk::gio::Cancellable>, |_| {});
            }
        });
    });
}

/// Closes the window, from any thread.
pub(super) fn quit() {
    glib::MainContext::default().invoke(|| {
        WINDOW.with(|v| {
            if let Some(window) = v.borrow().as_ref() {
                window.close();
            }
        });
    });
}

/// The desktop's own title bar moves the window; the page's strip is not a handle here.
pub(super) fn drag() {}

/// A double-click on the page's strip: maximise, or back.
pub(super) fn zoom() {
    glib::MainContext::default().invoke(|| {
        WINDOW.with(|v| {
            if let Some(window) = v.borrow().as_ref() {
                if window.is_maximized() { window.unmaximize() } else { window.maximize() }
            }
        });
    });
}

/// Settings → Appearance → Theme: GTK's dark variant for the title bar; the
/// page follows through `prefers-color-scheme`. "system" follows the desktop.
pub(super) fn set_appearance(theme: &str) {
    let theme = theme.to_owned();
    glib::MainContext::default().invoke(move || {
        let dark = match theme.as_str() {
            "dark" => true,
            "light" => false,
            _ => desktop_dark(),
        };
        if let Some(settings) = gtk::Settings::default() {
            settings.set_gtk_application_prefer_dark_theme(dark);
        }
        WEBVIEW.with(|v| {
            if let Some(webview) = v.borrow().as_ref() {
                webview.set_background_color(&page_background(dark));
            }
        });
    });
}

/// The view's background under the page: index.html's `--bg` for the scheme,
/// so there is no white flash before the page paints. Opaque on purpose: with
/// a transparent view and no GPU compositing (see `run`), WebKitGTK 2.54 keeps
/// only the regions repainted in each frame, and the rest of the window
/// flickers through to whatever is behind it.
fn page_background(dark: bool) -> gtk::gdk::RGBA {
    let (r, g, b) = if dark { (0x0F, 0x14, 0x19) } else { (0xF5, 0xF7, 0xFA) };
    gtk::gdk::RGBA::new(f64::from(r) / 255.0, f64::from(g) / 255.0, f64::from(b) / 255.0, 1.0)
}

/// GNOME's (and most desktops') dark preference, through the settings portal's key.
fn desktop_dark() -> bool {
    std::process::Command::new("gsettings")
        .args(["get", "org.gnome.desktop.interface", "color-scheme"])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("dark"))
}

/// The page can't write the clipboard itself.
pub(super) fn copy(text: &str) {
    let text = text.to_owned();
    glib::MainContext::default().invoke(move || {
        let clipboard = gtk::Clipboard::get(&gtk::gdk::SELECTION_CLIPBOARD);
        clipboard.set_text(&text);
        // Kept after the window quits, where the desktop has a clipboard manager.
        clipboard.store();
    });
}

/// The clipboard's text, handed to `done` once GTK has it.
pub(super) fn paste(done: impl FnOnce(String) + Send + 'static) {
    glib::MainContext::default().invoke(move || {
        gtk::Clipboard::get(&gtk::gdk::SELECTION_CLIPBOARD).request_text(move |_, text| done(text.map(|t| t.to_string()).unwrap_or_default()));
    });
}

/// Open a compose file…: GTK's own file chooser (the desktop's portal when
/// there is one), on GTK's main thread. Compose's file names first, any
/// YAML file second. `done` gets the path, or None when cancelled.
pub(super) fn pick_compose_file(title: &str, filters: &[String; 2], done: impl FnOnce(Option<std::path::PathBuf>) + Send + 'static) {
    let (title, filters) = (title.to_owned(), filters.clone());
    glib::MainContext::default().invoke(move || {
        let parent = WINDOW.with(|v| v.borrow().clone());
        let dialog = gtk::FileChooserNative::new(Some(&title), parent.as_ref(), gtk::FileChooserAction::Open, None, None);
        let names = gtk::FileFilter::new();
        names.set_name(Some(&filters[0]));
        for p in super::compose::FILE_NAMES {
            names.add_pattern(p);
        }
        let yaml = gtk::FileFilter::new();
        yaml.set_name(Some(&filters[1]));
        yaml.add_pattern("*.yaml");
        yaml.add_pattern("*.yml");
        dialog.add_filter(names);
        dialog.add_filter(yaml);
        let picked = if dialog.run() == gtk::ResponseType::Accept { dialog.filename() } else { None };
        dialog.destroy();
        done(picked);
    });
}

/// The installed font families, sorted; `mono` keeps the fixed-pitch ones.
pub(super) fn font_families(mono: bool) -> Vec<String> {
    let spacing = if mono { ":spacing=mono" } else { ":" };
    let Ok(out) = std::process::Command::new("fc-list").args([spacing, "family"]).output() else { return Vec::new() };
    let mut names: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        // "DejaVu Sans,DejaVu Sans Condensed": the first name is the family.
        .filter_map(|l| l.split(',').next().map(str::trim).filter(|n| !n.is_empty() && !n.starts_with('.')).map(str::to_owned))
        .collect();
    names.sort_by_key(|n| n.to_lowercase());
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use std::ffi::{c_char, c_int, c_void};
    use std::ptr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{FeatureApi, sym};

    #[test]
    fn sym_finds_loaded_symbols_and_rejects_missing_ones() {
        assert!(sym(c"dlsym").is_some());
        assert!(sym(c"webkit_no_such_symbol_in_kiri").is_none());
    }

    #[test]
    fn disable_damage_propagation_toggles_only_matching_feature_and_unrefs_list() {
        static UNREFS: AtomicUsize = AtomicUsize::new(0);
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        static LAST_SETTINGS: AtomicUsize = AtomicUsize::new(0);
        static LAST_FEATURE: AtomicUsize = AtomicUsize::new(0);
        static LAST_ENABLED: AtomicUsize = AtomicUsize::new(99);

        unsafe extern "C" fn all() -> *mut c_void {
            0x1000 as *mut c_void
        }
        unsafe extern "C" fn len(list: *mut c_void) -> usize {
            assert_eq!(list, 0x1000 as *mut c_void);
            4
        }
        unsafe extern "C" fn get(list: *mut c_void, idx: usize) -> *mut c_void {
            assert_eq!(list, 0x1000 as *mut c_void);
            match idx {
                0 => ptr::null_mut(),
                1 => 0x2001 as *mut c_void,
                2 => 0x2002 as *mut c_void,
                3 => 0x2003 as *mut c_void,
                _ => unreachable!(),
            }
        }
        unsafe extern "C" fn id(feature: *mut c_void) -> *const c_char {
            match feature as usize {
                0x2001 => ptr::null(),
                0x2002 => c"AcceleratedCompositing".as_ptr(),
                0x2003 => c"PropagateDamagingInformation".as_ptr(),
                _ => unreachable!(),
            }
        }
        unsafe extern "C" fn set(settings: *mut c_void, feature: *mut c_void, enabled: c_int) {
            CALLS.fetch_add(1, Ordering::SeqCst);
            LAST_SETTINGS.store(settings as usize, Ordering::SeqCst);
            LAST_FEATURE.store(feature as usize, Ordering::SeqCst);
            LAST_ENABLED.store(enabled as usize, Ordering::SeqCst);
        }
        unsafe extern "C" fn unref(list: *mut c_void) {
            assert_eq!(list, 0x1000 as *mut c_void);
            UNREFS.fetch_add(1, Ordering::SeqCst);
        }

        let api = FeatureApi {
            all,
            len,
            get,
            id,
            set,
            unref,
        };
        // SAFETY: the test callbacks above expect these sentinel pointers.
        unsafe { api.disable_damage_propagation(0x9000 as *mut c_void) };
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(LAST_SETTINGS.load(Ordering::SeqCst), 0x9000);
        assert_eq!(LAST_FEATURE.load(Ordering::SeqCst), 0x2003);
        assert_eq!(LAST_ENABLED.load(Ordering::SeqCst), 0);
        assert_eq!(UNREFS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn disable_damage_propagation_ignores_null_feature_list() {
        static UNREFS: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn all() -> *mut c_void {
            ptr::null_mut()
        }
        unsafe extern "C" fn len(_: *mut c_void) -> usize {
            unreachable!()
        }
        unsafe extern "C" fn get(_: *mut c_void, _: usize) -> *mut c_void {
            unreachable!()
        }
        unsafe extern "C" fn id(_: *mut c_void) -> *const c_char {
            unreachable!()
        }
        unsafe extern "C" fn set(_: *mut c_void, _: *mut c_void, _: c_int) {
            unreachable!()
        }
        unsafe extern "C" fn unref(_: *mut c_void) {
            UNREFS.fetch_add(1, Ordering::SeqCst);
        }

        let api = FeatureApi {
            all,
            len,
            get,
            id,
            set,
            unref,
        };
        // SAFETY: `all` returns null so no pointer is dereferenced.
        unsafe { api.disable_damage_propagation(ptr::null_mut()) };
        assert_eq!(UNREFS.load(Ordering::SeqCst), 0);
    }
}
