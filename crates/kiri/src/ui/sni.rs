//! The Linux tray (#405): `org.kde.StatusNotifierItem` and
//! `com.canonical.dbusmenu` over the session bus through `gtk::gio`, on
//! GTK's own main loop, with no extra crates.
//!
//! The menu matches the Mac menu bar item and the Windows tray: the engine's
//! state, up to 12 running containers (clicking one opens its page in the
//! window), Open Kiri, Start, Stop and Quit Kiri.
//!
//! `org.kde.StatusNotifierWatcher` is watched on the session bus:
//! [`tray_available`] is true only once the watcher has accepted the item,
//! and false again when the watcher leaves the bus. On a desktop without a
//! tray host (such as stock GNOME with no AppIndicator extension),
//! [`tray_available`] is false and closing the window quits `kiri ui` as
//! before, so the window never hides behind a tray icon that isn't there.
//! When the tray host goes away while the window is closed to it, the window
//! comes back.

#[cfg(target_os = "linux")]
use std::cell::RefCell;
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicU32;
#[cfg(target_os = "linux")]
use std::sync::mpsc::Sender;

#[cfg(target_os = "linux")]
use gtk::gdk_pixbuf::prelude::PixbufLoaderExt;
#[cfg(target_os = "linux")]
use gtk::gdk_pixbuf::{InterpType, PixbufLoader};
#[cfg(target_os = "linux")]
use gtk::gio;
#[cfg(target_os = "linux")]
use gtk::glib;
#[cfg(target_os = "linux")]
use gtk::prelude::*;

use super::MenuState;
#[cfg(target_os = "linux")]
use super::{Cmd, emit, json_str, menu_state, prefs};
#[cfg(target_os = "linux")]
use crate::diag;

#[cfg(target_os = "linux")]
const WATCHER_BUS: &str = "org.kde.StatusNotifierWatcher";
#[cfg(target_os = "linux")]
const WATCHER_PATH: &str = "/StatusNotifierWatcher";
#[cfg(target_os = "linux")]
const WATCHER_IFACE: &str = "org.kde.StatusNotifierWatcher";

#[cfg(target_os = "linux")]
const ITEM_PATH: &str = "/StatusNotifierItem";
#[cfg(target_os = "linux")]
const ITEM_IFACE: &str = "org.kde.StatusNotifierItem";

#[cfg(target_os = "linux")]
const MENU_PATH: &str = "/MenuBar";
#[cfg(target_os = "linux")]
const MENU_IFACE: &str = "com.canonical.dbusmenu";

#[cfg(target_os = "linux")]
const ID_ROOT: i32 = 0;
const ID_STATE: i32 = 1;
const ID_SEP_TOP: i32 = 2;
const ID_EMPTY: i32 = 3;
const ID_MORE: i32 = 4;
const ID_SEP_MID: i32 = 5;
const ID_OPEN: i32 = 6;
const ID_START: i32 = 7;
const ID_STOP: i32 = 8;
const ID_SEP_BOT: i32 = 9;
const ID_QUIT: i32 = 10;
const ID_CONTAINER: i32 = 100;
const MAX_CONTAINERS: usize = 12;

#[cfg(target_os = "linux")]
const INTROSPECTION_XML: &str = r#"
<node>
  <interface name="org.kde.StatusNotifierItem">
    <property name="Category" type="s" access="read"/>
    <property name="Id" type="s" access="read"/>
    <property name="Title" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="WindowId" type="i" access="read"/>
    <property name="IconName" type="s" access="read"/>
    <property name="IconPixmap" type="a(iiay)" access="read"/>
    <property name="OverlayIconName" type="s" access="read"/>
    <property name="OverlayIconPixmap" type="a(iiay)" access="read"/>
    <property name="AttentionIconName" type="s" access="read"/>
    <property name="AttentionIconPixmap" type="a(iiay)" access="read"/>
    <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
    <property name="ItemIsMenu" type="b" access="read"/>
    <property name="Menu" type="o" access="read"/>
    <method name="ContextMenu">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="Activate">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="SecondaryActivate">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="Scroll">
      <arg name="delta" type="i" direction="in"/>
      <arg name="orientation" type="s" direction="in"/>
    </method>
    <method name="ProvideXdgActivationToken">
      <arg name="token" type="s" direction="in"/>
    </method>
    <signal name="NewTitle"/>
    <signal name="NewIcon"/>
    <signal name="NewAttentionIcon"/>
    <signal name="NewOverlayIcon"/>
    <signal name="NewToolTip"/>
    <signal name="NewStatus">
      <arg name="status" type="s"/>
    </signal>
  </interface>
  <interface name="com.canonical.dbusmenu">
    <property name="Version" type="u" access="read"/>
    <property name="TextDirection" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="IconThemePath" type="as" access="read"/>
    <method name="GetLayout">
      <arg name="parentId" type="i" direction="in"/>
      <arg name="recursionDepth" type="i" direction="in"/>
      <arg name="propertyNames" type="as" direction="in"/>
      <arg name="revision" type="u" direction="out"/>
      <arg name="layout" type="(ia{sv}av)" direction="out"/>
    </method>
    <method name="GetGroupProperties">
      <arg name="ids" type="ai" direction="in"/>
      <arg name="propertyNames" type="as" direction="in"/>
      <arg name="properties" type="a(ia{sv})" direction="out"/>
    </method>
    <method name="GetProperty">
      <arg name="id" type="i" direction="in"/>
      <arg name="name" type="s" direction="in"/>
      <arg name="value" type="v" direction="out"/>
    </method>
    <method name="Event">
      <arg name="id" type="i" direction="in"/>
      <arg name="eventId" type="s" direction="in"/>
      <arg name="data" type="v" direction="in"/>
      <arg name="timestamp" type="u" direction="in"/>
    </method>
    <method name="EventGroup">
      <arg name="events" type="a(isvu)" direction="in"/>
      <arg name="idErrors" type="ai" direction="out"/>
    </method>
    <method name="AboutToShow">
      <arg name="id" type="i" direction="in"/>
      <arg name="needUpdate" type="b" direction="out"/>
    </method>
    <method name="AboutToShowGroup">
      <arg name="ids" type="ai" direction="in"/>
      <arg name="updatesNeeded" type="ai" direction="out"/>
      <arg name="idErrors" type="ai" direction="out"/>
    </method>
    <signal name="ItemsPropertiesUpdated">
      <arg name="updatedProps" type="a(ia{sv})"/>
      <arg name="removedProps" type="a(ias)"/>
    </signal>
    <signal name="LayoutUpdated">
      <arg name="revision" type="u"/>
      <arg name="parent" type="i"/>
    </signal>
    <signal name="ItemActivationRequested">
      <arg name="id" type="i"/>
      <arg name="timestamp" type="u"/>
    </signal>
  </interface>
</node>
"#;

static AVAILABLE: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "linux")]
static REVISION: AtomicU32 = AtomicU32::new(1);

#[cfg(target_os = "linux")]
struct Registration {
    _conn: gio::DBusConnection,
    _item: gio::RegistrationId,
    _menu: gio::RegistrationId,
    /// Stops watching `org.kde.StatusNotifierWatcher`. gio 0.18 keeps the
    /// id type `bus_watch_name_on_connection` returns in a private module,
    /// so the id is held inside this closure instead of a field.
    unwatch: Option<Box<dyn FnOnce()>>,
}

#[cfg(target_os = "linux")]
impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(unwatch) = self.unwatch.take() {
            unwatch();
        }
    }
}

#[cfg(target_os = "linux")]
thread_local! {
    static REG: RefCell<Option<Registration>> = const { RefCell::new(None) };
}

/// Whether a `StatusNotifierWatcher` currently owns the bus name and accepted
/// Kiri's tray item. Only then does closing the window hide or release its
/// page instead of quitting `kiri ui`.
pub(super) fn tray_available() -> bool {
    AVAILABLE.load(Ordering::SeqCst)
}

fn set_watcher_online(has_owner: bool) -> bool {
    AVAILABLE.store(has_owner, Ordering::SeqCst);
    has_owner
}

/// The watcher left the bus or refused the item: the tray is gone, and
/// `on_lost` brings back a window that was closed to it.
#[cfg(target_os = "linux")]
fn tray_lost(on_lost: &dyn Fn()) {
    set_watcher_online(false);
    on_lost();
}

/// Exports `org.kde.StatusNotifierItem` and `com.canonical.dbusmenu` on the
/// session bus and watches `org.kde.StatusNotifierWatcher`.
#[cfg(target_os = "linux")]
pub(super) fn start(tx: Sender<Cmd>, icon_png: &[u8]) {
    let conn = match gio::bus_get_sync(gio::BusType::Session, None::<&gio::Cancellable>) {
        Ok(c) => c,
        Err(e) => {
            diag::warn!("session bus not reached for tray", error = e.to_string());
            return;
        }
    };
    match register_on(&conn, tx, icon_png, super::window::show, super::window::tray_gone) {
        Ok(reg) => REG.with(|r| *r.borrow_mut() = Some(reg)),
        Err(e) => diag::warn!("tray not registered", error = e.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn register_on(
    conn: &gio::DBusConnection,
    tx: Sender<Cmd>,
    icon_png: &[u8],
    on_activate: impl Fn() + Send + Sync + 'static,
    on_lost: impl Fn() + Send + Sync + 'static,
) -> Result<Registration, glib::Error> {
    let node = gio::DBusNodeInfo::for_xml(INTROSPECTION_XML)?;
    let item_info = node
        .lookup_interface(ITEM_IFACE)
        .ok_or_else(|| glib::Error::new(gio::IOErrorEnum::Failed, "missing StatusNotifierItem interface"))?;
    let menu_info = node
        .lookup_interface(MENU_IFACE)
        .ok_or_else(|| glib::Error::new(gio::IOErrorEnum::Failed, "missing dbusmenu interface"))?;

    let icons = Arc::new(pixmaps_variant(&pixmap(icon_png)));
    let item_icons = Arc::clone(&icons);
    let activate = Arc::new(on_activate);
    let item_activate = Arc::clone(&activate);

    let item = conn.register_object(
        ITEM_PATH,
        &item_info,
        move |_conn, _sender, _path, _iface, method, _params, invocation| match method {
            "Activate" | "SecondaryActivate" => {
                item_activate();
                invocation.return_value(None);
            }
            "ContextMenu" | "Scroll" | "ProvideXdgActivationToken" => {
                invocation.return_value(None);
            }
            _ => invocation.return_dbus_error("org.freedesktop.DBus.Error.UnknownMethod", "Unknown method"),
        },
        move |_conn, _sender, _path, _iface, prop| sni_property(prop, &item_icons),
        |_conn, _sender, _path, _iface, _prop, _val| false,
    )?;

    let shown: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let menu_shown = Arc::clone(&shown);
    let menu_activate = Arc::clone(&activate);
    let menu = conn.register_object(
        MENU_PATH,
        &menu_info,
        move |_conn, _sender, _path, _iface, method, params, invocation| {
            handle_menu_method(method, &params, invocation, &tx, &menu_shown, &*menu_activate);
        },
        |_conn, _sender, _path, _iface, prop| menu_property(prop),
        |_conn, _sender, _path, _iface, _prop, _val| false,
    )?;

    let lost: Arc<dyn Fn() + Send + Sync> = Arc::new(on_lost);
    let appeared_lost = Arc::clone(&lost);
    let watch = gio::bus_watch_name_on_connection(
        conn,
        WATCHER_BUS,
        gio::BusNameWatcherFlags::NONE,
        move |conn, _name, _owner| register_with_watcher(&conn, Arc::clone(&appeared_lost)),
        move |_conn, _name| tray_lost(&*lost),
    );

    Ok(Registration {
        _conn: conn.clone(),
        _item: item,
        _menu: menu,
        unwatch: Some(Box::new(move || gio::bus_unwatch_name(watch))),
    })
}

/// Asks the watcher to show the item; the tray counts as up only once the
/// watcher has said yes.
#[cfg(target_os = "linux")]
fn register_with_watcher(conn: &gio::DBusConnection, on_lost: Arc<dyn Fn() + Send + Sync>) {
    let service = conn
        .unique_name()
        .map_or_else(|| ITEM_PATH.to_owned(), |n| n.to_string());
    conn.call(
        Some(WATCHER_BUS),
        WATCHER_PATH,
        WATCHER_IFACE,
        "RegisterStatusNotifierItem",
        Some(&(service,).to_variant()),
        None,
        gio::DBusCallFlags::NONE,
        5000,
        None::<&gio::Cancellable>,
        move |res| match res {
            Ok(_) => {
                set_watcher_online(true);
            }
            Err(e) => {
                diag::warn!("tray watcher rejected item", error = e.to_string());
                tray_lost(&*on_lost);
            }
        },
    );
}

/// Converts raw `GdkPixbuf` rows (RGBA or RGB, with rowstride padding) into
/// network-byte-order ARGB32 (`[a, r, g, b]` per pixel), as
/// `org.kde.StatusNotifierItem.IconPixmap` expects.
fn rgba_to_argb32(bytes: &[u8], width: usize, height: usize, stride: usize, has_alpha: bool) -> Vec<u8> {
    let channels = if has_alpha { 4 } else { 3 };
    let mut out = Vec::with_capacity(width * height * 4);
    for y in 0..height {
        for x in 0..width {
            let i = y * stride + x * channels;
            let (r, g, b, a) = if has_alpha {
                (bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3])
            } else {
                (bytes[i], bytes[i + 1], bytes[i + 2], 0xFF)
            };
            out.extend_from_slice(&[a, r, g, b]);
        }
    }
    out
}

/// Scales `png` to 22 px and 32 px ARGB32 icon bitmaps for `IconPixmap`.
#[cfg(target_os = "linux")]
fn pixmap(png: &[u8]) -> Vec<(i32, i32, Vec<u8>)> {
    let loader = PixbufLoader::new();
    if loader.write(png).is_err() || loader.close().is_err() {
        return Vec::new();
    }
    let Some(full) = loader.pixbuf() else { return Vec::new() };
    [22, 32]
        .iter()
        .filter_map(|&size| {
            let scaled = full.scale_simple(size, size, InterpType::Bilinear)?;
            let bytes = scaled.read_pixel_bytes();
            let (w, h) = (scaled.width() as usize, scaled.height() as usize);
            let data = rgba_to_argb32(&bytes, w, h, scaled.rowstride() as usize, scaled.has_alpha());
            Some((size, size, data))
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn pixmaps_variant(icons: &[(i32, i32, Vec<u8>)]) -> glib::Variant {
    let ty = glib::VariantTy::new("(iiay)").unwrap();
    glib::Variant::array_from_iter_with_type(
        ty,
        icons.iter().map(|(w, h, data)| {
            glib::Variant::tuple_from_iter([
                w.to_variant(),
                h.to_variant(),
                glib::Variant::array_from_fixed_array::<u8>(data),
            ])
        }),
    )
}

#[cfg(target_os = "linux")]
fn empty_pixmaps() -> glib::Variant {
    pixmaps_variant(&[])
}

#[cfg(target_os = "linux")]
fn sni_property(name: &str, icons: &glib::Variant) -> glib::Variant {
    let app = crate::flavor::APP.get();
    match name {
        "Category" => "ApplicationStatus".to_variant(),
        "Id" => "kiri".to_variant(),
        "Title" => app.to_variant(),
        "Status" => "Active".to_variant(),
        "WindowId" => 0i32.to_variant(),
        "IconName" | "OverlayIconName" | "AttentionIconName" => "".to_variant(),
        "IconPixmap" => icons.clone(),
        "OverlayIconPixmap" | "AttentionIconPixmap" => empty_pixmaps(),
        "ToolTip" => glib::Variant::tuple_from_iter([
            "".to_variant(),
            empty_pixmaps(),
            app.to_variant(),
            "".to_variant(),
        ]),
        "ItemIsMenu" => false.to_variant(),
        "Menu" => glib::variant::ObjectPath::try_from(MENU_PATH).unwrap().to_variant(),
        _ => "".to_variant(),
    }
}

#[cfg(target_os = "linux")]
fn menu_property(name: &str) -> glib::Variant {
    match name {
        "Version" => 3u32.to_variant(),
        "TextDirection" => {
            let rtl = super::lang::rtl(super::lang::resolve(prefs()["lang"].as_str()));
            (if rtl { "rtl" } else { "ltr" }).to_variant()
        }
        "Status" => "normal".to_variant(),
        "IconThemePath" => Vec::<String>::new().to_variant(),
        _ => "".to_variant(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MenuEntry {
    Item { id: i32, label: String, enabled: bool },
    Separator { id: i32 },
}

#[cfg(target_os = "linux")]
impl MenuEntry {
    fn id(&self) -> i32 {
        match self {
            MenuEntry::Item { id, .. } | MenuEntry::Separator { id } => *id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MenuAction {
    OpenWindow,
    OpenContainer(String),
    Start,
    Stop,
    Quit,
}

fn menu_entries(state: &MenuState, lang: &str) -> (Vec<MenuEntry>, Vec<String>) {
    let tr = |en: &str| super::lang::tr(lang, en);
    let trf = |en: &str, vars: &[(&str, &dyn std::fmt::Display)]| super::lang::fill(tr(en), vars);
    let mut items = vec![
        MenuEntry::Item {
            id: ID_STATE,
            label: trf("Kiri: {state}", &[("state", &tr(state.vm))]),
            enabled: false,
        },
        MenuEntry::Separator { id: ID_SEP_TOP },
    ];
    let mut shown = Vec::new();
    if state.running.is_empty() {
        items.push(MenuEntry::Item {
            id: ID_EMPTY,
            label: tr("No containers running"),
            enabled: false,
        });
    }
    for (i, (id, name, url)) in state.running.iter().take(MAX_CONTAINERS).enumerate() {
        let title = match url {
            Some(u) => format!("{name}  ·  {}", u.trim_start_matches("http://")),
            None => name.clone(),
        };
        items.push(MenuEntry::Item {
            id: ID_CONTAINER + i as i32,
            label: title,
            enabled: true,
        });
        shown.push(id.clone());
    }
    if state.running.len() > MAX_CONTAINERS {
        items.push(MenuEntry::Item {
            id: ID_MORE,
            label: trf("and {n} more…", &[("n", &(state.running.len() - MAX_CONTAINERS).to_string())]),
            enabled: true,
        });
    }
    items.extend([
        MenuEntry::Separator { id: ID_SEP_MID },
        MenuEntry::Item { id: ID_OPEN, label: tr("Open Kiri"), enabled: true },
        MenuEntry::Item { id: ID_START, label: tr("Start"), enabled: true },
        MenuEntry::Item { id: ID_STOP, label: tr("Stop"), enabled: true },
        MenuEntry::Separator { id: ID_SEP_BOT },
        MenuEntry::Item { id: ID_QUIT, label: tr("Quit Kiri"), enabled: true },
    ]);
    (items, shown)
}

fn action_for_id(id: i32, shown: &[String]) -> Option<MenuAction> {
    match id {
        ID_OPEN | ID_MORE => Some(MenuAction::OpenWindow),
        ID_START => Some(MenuAction::Start),
        ID_STOP => Some(MenuAction::Stop),
        ID_QUIT => Some(MenuAction::Quit),
        n if n >= ID_CONTAINER => {
            let idx = usize::try_from(n - ID_CONTAINER).ok()?;
            shown.get(idx).cloned().map(MenuAction::OpenContainer)
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn vardict(entries: &[(&str, glib::Variant)]) -> glib::Variant {
    let ty = glib::VariantTy::new("{sv}").unwrap();
    glib::Variant::array_from_iter_with_type(
        ty,
        entries.iter().map(|(k, v)| {
            glib::Variant::from_dict_entry(&k.to_variant(), &glib::Variant::from_variant(v))
        }),
    )
}

#[cfg(target_os = "linux")]
fn entry_props(entry: &MenuEntry) -> glib::Variant {
    match entry {
        MenuEntry::Item { label, enabled, .. } => vardict(&[
            ("label", label.to_variant()),
            ("enabled", enabled.to_variant()),
            ("visible", true.to_variant()),
        ]),
        MenuEntry::Separator { .. } => vardict(&[
            ("type", "separator".to_variant()),
            ("visible", true.to_variant()),
        ]),
    }
}

#[cfg(target_os = "linux")]
fn entry_node(entry: &MenuEntry) -> glib::Variant {
    let empty_children = glib::Variant::array_from_iter::<glib::Variant>(std::iter::empty());
    glib::Variant::tuple_from_iter([entry.id().to_variant(), entry_props(entry), empty_children])
}

#[cfg(target_os = "linux")]
fn layout_variant(revision: u32, parent_id: i32, recursion_depth: i32, entries: &[MenuEntry]) -> glib::Variant {
    if parent_id == ID_ROOT {
        let children = if recursion_depth == 0 {
            glib::Variant::array_from_iter::<glib::Variant>(std::iter::empty())
        } else {
            glib::Variant::array_from_iter::<glib::Variant>(
                entries.iter().map(|e| glib::Variant::from_variant(&entry_node(e))),
            )
        };
        let root = glib::Variant::tuple_from_iter([
            ID_ROOT.to_variant(),
            vardict(&[("children-display", "submenu".to_variant())]),
            children,
        ]);
        return glib::Variant::tuple_from_iter([revision.to_variant(), root]);
    }
    let node = entries.iter().find(|e| e.id() == parent_id).map_or_else(
        || {
            let empty_children = glib::Variant::array_from_iter::<glib::Variant>(std::iter::empty());
            glib::Variant::tuple_from_iter([parent_id.to_variant(), vardict(&[]), empty_children])
        },
        entry_node,
    );
    glib::Variant::tuple_from_iter([revision.to_variant(), node])
}

#[cfg(target_os = "linux")]
fn handle_menu_method(
    method: &str,
    params: &glib::Variant,
    invocation: gio::DBusMethodInvocation,
    tx: &Sender<Cmd>,
    shown: &Mutex<Vec<String>>,
    on_open: &dyn Fn(),
) {
    let current_entries = || {
        let state = menu_state();
        let lang = super::lang::resolve(prefs()["lang"].as_str());
        let (entries, ids) = menu_entries(&state, lang);
        *shown.lock().unwrap_or_else(|e| e.into_inner()) = ids;
        entries
    };
    let trigger = |id: i32| {
        let mut ids = shown.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if ids.is_empty() {
            ids = menu_state().running.iter().take(MAX_CONTAINERS).map(|(c, _, _)| c.clone()).collect();
        }
        match action_for_id(id, &ids) {
            Some(MenuAction::OpenWindow) => on_open(),
            Some(MenuAction::OpenContainer(cid)) => {
                on_open();
                let mut ev = String::from(r#"{"type":"detail","id":"#);
                json_str(&mut ev, &cid);
                ev.push('}');
                emit(ev);
            }
            Some(MenuAction::Start) => {
                let _ = tx.send(Cmd::Start);
            }
            Some(MenuAction::Stop) => {
                let _ = tx.send(Cmd::Stop);
            }
            Some(MenuAction::Quit) => super::window::quit(),
            None => {}
        }
    };

    match method {
        "GetLayout" => {
            let parent_id = params.try_child_get::<i32>(0).ok().flatten().unwrap_or(ID_ROOT);
            let depth = params.try_child_get::<i32>(1).ok().flatten().unwrap_or(-1);
            let entries = current_entries();
            let rev = REVISION.fetch_add(1, Ordering::Relaxed);
            let reply = layout_variant(rev, parent_id, depth, &entries);
            invocation.return_value(Some(&reply));
        }
        "GetGroupProperties" => {
            let ids = params.try_child_get::<Vec<i32>>(0).ok().flatten().unwrap_or_default();
            let entries = current_entries();
            let item_ty = glib::VariantTy::new("(ia{sv})").unwrap();
            let list = glib::Variant::array_from_iter_with_type(
                item_ty,
                ids.into_iter().filter_map(|id| {
                    if id == ID_ROOT {
                        Some(glib::Variant::tuple_from_iter([
                            ID_ROOT.to_variant(),
                            vardict(&[("children-display", "submenu".to_variant())]),
                        ]))
                    } else {
                        entries.iter().find(|e| e.id() == id).map(|e| {
                            glib::Variant::tuple_from_iter([id.to_variant(), entry_props(e)])
                        })
                    }
                }),
            );
            let reply = glib::Variant::tuple_from_iter([list]);
            invocation.return_value(Some(&reply));
        }
        "GetProperty" => {
            let id = params.try_child_get::<i32>(0).ok().flatten().unwrap_or(ID_ROOT);
            let name = params.try_child_get::<String>(1).ok().flatten().unwrap_or_default();
            let entries = current_entries();
            let val = match (entries.iter().find(|e| e.id() == id), name.as_str()) {
                (Some(MenuEntry::Item { label, .. }), "label") => label.to_variant(),
                (Some(MenuEntry::Item { enabled, .. }), "enabled") => enabled.to_variant(),
                (Some(MenuEntry::Separator { .. }), "type") => "separator".to_variant(),
                (_, "visible") => true.to_variant(),
                _ => "".to_variant(),
            };
            let reply = glib::Variant::tuple_from_iter([glib::Variant::from_variant(&val)]);
            invocation.return_value(Some(&reply));
        }
        "Event" => {
            let id = params.try_child_get::<i32>(0).ok().flatten().unwrap_or(-1);
            let event_id = params.try_child_get::<String>(1).ok().flatten().unwrap_or_default();
            if event_id == "clicked" {
                trigger(id);
            }
            invocation.return_value(None);
        }
        "EventGroup" => {
            if let Some(events) = params.try_child_value(0) {
                for i in 0..events.n_children() {
                    let ev = events.child_value(i);
                    let id = ev.try_child_get::<i32>(0).ok().flatten().unwrap_or(-1);
                    let kind = ev.try_child_get::<String>(1).ok().flatten().unwrap_or_default();
                    if kind == "clicked" {
                        trigger(id);
                    }
                }
            }
            let reply = glib::Variant::tuple_from_iter([Vec::<i32>::new().to_variant()]);
            invocation.return_value(Some(&reply));
        }
        "AboutToShow" => {
            let reply = glib::Variant::tuple_from_iter([true.to_variant()]);
            invocation.return_value(Some(&reply));
        }
        "AboutToShowGroup" => {
            let reply = glib::Variant::tuple_from_iter([
                vec![ID_ROOT].to_variant(),
                Vec::<i32>::new().to_variant(),
            ]);
            invocation.return_value(Some(&reply));
        }
        _ => invocation.return_dbus_error("org.freedesktop.DBus.Error.UnknownMethod", "Unknown method"),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::io::BufRead;
    #[cfg(target_os = "linux")]
    use std::process::{Child, Command, Stdio};
    #[cfg(target_os = "linux")]
    use std::sync::Arc;
    #[cfg(target_os = "linux")]
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    #[cfg(target_os = "linux")]
    use std::sync::mpsc;
    #[cfg(target_os = "linux")]
    use std::time::{Duration, Instant};

    use super::*;

    /// `AVAILABLE` is one static shared by every test in the process.
    static TRAY_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    #[test]
    fn argb32_conversion_handles_rgba_rgb_and_rowstride_padding() {
        // 2x2 RGBA with 2 bytes of rowstride padding per row (stride = 10).
        let rgba = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xFF, 0xFF,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01, 0x02, 0xFF, 0xFF,
        ];
        let out = rgba_to_argb32(&rgba, 2, 2, 10, true);
        assert_eq!(
            out,
            vec![
                0x44, 0x11, 0x22, 0x33,
                0x88, 0x55, 0x66, 0x77,
                0xCC, 0x99, 0xAA, 0xBB,
                0x02, 0xDD, 0xEE, 0x01,
            ]
        );

        // 2x1 RGB without alpha (3 bytes per pixel) gets 0xFF alpha first.
        let rgb = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        assert_eq!(
            rgba_to_argb32(&rgb, 2, 1, 6, false),
            vec![0xFF, 0x10, 0x20, 0x30, 0xFF, 0x40, 0x50, 0x60]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn icon_png_scales_to_22_and_32_argb32_pixmaps() {
        let icons = pixmap(super::super::window::ICON_PNG);
        assert_eq!(icons.len(), 2);
        assert_eq!((icons[0].0, icons[0].1, icons[0].2.len()), (22, 22, 22 * 22 * 4));
        assert_eq!((icons[1].0, icons[1].1, icons[1].2.len()), (32, 32, 32 * 32 * 4));
        let v = pixmaps_variant(&icons);
        assert_eq!(v.type_().as_str(), "a(iiay)");
        assert_eq!(v.n_children(), 2);
    }

    #[test]
    fn watcher_availability_transitions_online_and_offline() {
        let _state = TRAY_STATE.lock().unwrap_or_else(|e| e.into_inner());
        set_watcher_online(false);
        assert!(!tray_available());
        assert!(set_watcher_online(true));
        assert!(tray_available());
        assert!(!set_watcher_online(false));
        assert!(!tray_available());
    }

    #[test]
    fn dbusmenu_layout_caps_running_containers_at_twelve_and_maps_actions() {
        let empty_state = MenuState { vm: "Stopped", running: Vec::new() };
        let (entries, shown) = menu_entries(&empty_state, "en");
        assert!(shown.is_empty());
        assert_eq!(
            entries,
            vec![
                MenuEntry::Item { id: ID_STATE, label: "Kiri: Stopped".into(), enabled: false },
                MenuEntry::Separator { id: ID_SEP_TOP },
                MenuEntry::Item { id: ID_EMPTY, label: "No containers running".into(), enabled: false },
                MenuEntry::Separator { id: ID_SEP_MID },
                MenuEntry::Item { id: ID_OPEN, label: "Open Kiri".into(), enabled: true },
                MenuEntry::Item { id: ID_START, label: "Start".into(), enabled: true },
                MenuEntry::Item { id: ID_STOP, label: "Stop".into(), enabled: true },
                MenuEntry::Separator { id: ID_SEP_BOT },
                MenuEntry::Item { id: ID_QUIT, label: "Quit Kiri".into(), enabled: true },
            ]
        );

        let running: Vec<(String, String, Option<String>)> = (0..14)
            .map(|i| {
                let url = (i == 0).then(|| "http://web.kiri.localhost".to_owned());
                (format!("cid-{i}"), format!("app-{i}"), url)
            })
            .collect();
        let busy_state = MenuState { vm: "Running", running };
        let (entries, shown) = menu_entries(&busy_state, "en");
        assert_eq!(shown.len(), 12);
        assert_eq!(shown[0], "cid-0");
        assert_eq!(shown[11], "cid-11");
        assert!(entries.contains(&MenuEntry::Item {
            id: ID_CONTAINER,
            label: "app-0  ·  web.kiri.localhost".into(),
            enabled: true,
        }));
        assert!(entries.contains(&MenuEntry::Item {
            id: ID_MORE,
            label: "and 2 more…".into(),
            enabled: true,
        }));

        #[cfg(target_os = "linux")]
        {
            // Verify GVariant signature and structure of GetLayout reply.
            let layout = layout_variant(7, ID_ROOT, -1, &entries);
            assert_eq!(layout.type_().as_str(), "(u(ia{sv}av))");
            assert_eq!(layout.child_get::<u32>(0), 7);
            let root = layout.child_value(1);
            assert_eq!(root.child_get::<i32>(0), ID_ROOT);
            assert_eq!(root.child_value(2).n_children(), entries.len());
        }

        // Action lookup for menu item IDs.
        assert_eq!(action_for_id(ID_OPEN, &shown), Some(MenuAction::OpenWindow));
        assert_eq!(action_for_id(ID_MORE, &shown), Some(MenuAction::OpenWindow));
        assert_eq!(action_for_id(ID_START, &shown), Some(MenuAction::Start));
        assert_eq!(action_for_id(ID_STOP, &shown), Some(MenuAction::Stop));
        assert_eq!(action_for_id(ID_QUIT, &shown), Some(MenuAction::Quit));
        assert_eq!(action_for_id(ID_CONTAINER, &shown), Some(MenuAction::OpenContainer("cid-0".into())));
        assert_eq!(action_for_id(ID_CONTAINER + 11, &shown), Some(MenuAction::OpenContainer("cid-11".into())));
        assert_eq!(action_for_id(ID_CONTAINER + 12, &shown), None);
        assert_eq!(action_for_id(ID_STATE, &shown), None);
    }

    #[cfg(target_os = "linux")]
    struct PrivateBus {
        child: Child,
        address: String,
    }

    #[cfg(target_os = "linux")]
    impl PrivateBus {
        fn spawn() -> Option<Self> {
            let mut child = Command::new("dbus-daemon")
                .args(["--session", "--nofork", "--print-address=1"])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .ok()?;
            let stdout = child.stdout.take()?;
            let mut reader = std::io::BufReader::new(stdout);
            let mut address = String::new();
            reader.read_line(&mut address).ok()?;
            let address = address.trim().to_owned();
            if address.is_empty() {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Some(Self { child, address })
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for PrivateBus {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[cfg(target_os = "linux")]
    fn pump_until(ctx: &glib::MainContext, timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            while ctx.iteration(false) {}
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        while ctx.iteration(false) {}
        pred()
    }

    #[cfg(target_os = "linux")]
    fn call_async(
        conn: &gio::DBusConnection,
        ctx: &glib::MainContext,
        bus_name: &str,
        object_path: &str,
        interface_name: &str,
        method_name: &str,
        params: Option<&glib::Variant>,
    ) -> glib::Variant {
        let result: Arc<Mutex<Option<Result<glib::Variant, glib::Error>>>> = Arc::new(Mutex::new(None));
        let slot = Arc::clone(&result);
        conn.call(
            Some(bus_name),
            object_path,
            interface_name,
            method_name,
            params,
            None,
            gio::DBusCallFlags::NONE,
            5000,
            None::<&gio::Cancellable>,
            move |res| {
                *slot.lock().unwrap() = Some(res);
            },
        );
        assert!(
            pump_until(ctx, Duration::from_secs(5), || result.lock().unwrap().is_some()),
            "D-Bus call {interface_name}.{method_name} timed out"
        );
        result.lock().unwrap().take().unwrap().unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_gdbus_status_notifier_registers_serves_icon_layout_and_activates() {
        let bus = PrivateBus::spawn().expect("dbus-daemon must be available");
        let ctx = glib::MainContext::default();
        let _guard = ctx.acquire().expect("acquire main context");

        let flags = gio::DBusConnectionFlags::AUTHENTICATION_CLIENT
            | gio::DBusConnectionFlags::MESSAGE_BUS_CONNECTION;
        let watcher_conn = gio::DBusConnection::for_address_sync(&bus.address, flags, None, None::<&gio::Cancellable>).unwrap();
        let item_conn = gio::DBusConnection::for_address_sync(&bus.address, flags, None, None::<&gio::Cancellable>).unwrap();

        let _state = TRAY_STATE.lock().unwrap_or_else(|e| e.into_inner());
        set_watcher_online(false);
        let (tx, rx) = mpsc::channel();
        let activated = Arc::new(AtomicUsize::new(0));
        let act_count = Arc::clone(&activated);
        let lost = Arc::new(AtomicUsize::new(0));
        let lost_count = Arc::clone(&lost);
        let _reg = register_on(
            &item_conn,
            tx,
            super::super::window::ICON_PNG,
            move || {
                act_count.fetch_add(1, Ordering::SeqCst);
            },
            move || {
                lost_count.fetch_add(1, Ordering::SeqCst);
            },
        )
        .unwrap();

        // With no StatusNotifierWatcher on the bus yet, tray_available() stays false.
        pump_until(&ctx, Duration::from_millis(50), || false);
        assert!(!tray_available(), "tray must be unavailable before watcher appears");

        // Export a mock org.kde.StatusNotifierWatcher that refuses items
        // until `accept` is set.
        let watcher_xml = r#"
        <node>
          <interface name="org.kde.StatusNotifierWatcher">
            <method name="RegisterStatusNotifierItem">
              <arg name="service" type="s" direction="in"/>
            </method>
          </interface>
        </node>
        "#;
        let watcher_node = gio::DBusNodeInfo::for_xml(watcher_xml).unwrap();
        let watcher_iface = watcher_node.lookup_interface(WATCHER_IFACE).unwrap();
        let accept = Arc::new(AtomicBool::new(false));
        let watcher_accept = Arc::clone(&accept);
        let refused = Arc::new(AtomicUsize::new(0));
        let refused_count = Arc::clone(&refused);
        let registered_service: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let reg_slot = Arc::clone(&registered_service);
        let _watcher_obj = watcher_conn
            .register_object(
                WATCHER_PATH,
                &watcher_iface,
                move |_conn, _sender, _path, _iface, method, params, invocation| {
                    if method != "RegisterStatusNotifierItem" {
                        return;
                    }
                    if !watcher_accept.load(Ordering::SeqCst) {
                        refused_count.fetch_add(1, Ordering::SeqCst);
                        invocation.return_dbus_error("org.freedesktop.DBus.Error.Failed", "refused");
                        return;
                    }
                    let svc = params.child_get::<String>(0);
                    *reg_slot.lock().unwrap() = Some(svc);
                    invocation.return_value(None);
                },
                |_conn, _sender, _path, _iface, _prop| "".to_variant(),
                |_conn, _sender, _path, _iface, _prop, _val| false,
            )
            .unwrap();

        let bus_call = |method: &str, params: glib::Variant| {
            watcher_conn
                .call_sync(
                    Some("org.freedesktop.DBus"),
                    "/org/freedesktop/DBus",
                    "org.freedesktop.DBus",
                    method,
                    Some(&params),
                    None,
                    gio::DBusCallFlags::NONE,
                    5000,
                    None::<&gio::Cancellable>,
                )
                .unwrap()
        };
        let request_name = || {
            let req = bus_call("RequestName", (WATCHER_BUS, 0u32).to_variant());
            assert_eq!(req.child_get::<u32>(0), 1, "mock watcher should own bus name");
        };
        let release_name = || {
            bus_call("ReleaseName", (WATCHER_BUS,).to_variant());
        };

        // A watcher that refuses the item leaves the tray unavailable, and
        // the window is called back.
        let lost_before = lost.load(Ordering::SeqCst);
        request_name();
        assert!(
            pump_until(&ctx, Duration::from_secs(5), || {
                refused.load(Ordering::SeqCst) == 1 && lost.load(Ordering::SeqCst) > lost_before
            }),
            "refused registration must report the tray lost"
        );
        assert!(!tray_available(), "tray must stay unavailable when the watcher refuses the item");

        // That watcher leaves the bus: the window is called back again.
        let lost_before = lost.load(Ordering::SeqCst);
        release_name();
        assert!(
            pump_until(&ctx, Duration::from_secs(5), || lost.load(Ordering::SeqCst) > lost_before),
            "watcher vanishing must report the tray lost"
        );

        // A watcher that accepts the item makes the tray available.
        accept.store(true, Ordering::SeqCst);
        request_name();
        assert!(
            pump_until(&ctx, Duration::from_secs(5), || {
                registered_service.lock().unwrap().is_some() && tray_available()
            }),
            "StatusNotifierItem did not register with watcher"
        );
        let item_bus = registered_service.lock().unwrap().clone().unwrap();
        assert_eq!(Some(item_bus.as_str()), item_conn.unique_name().as_deref());

        // 1. Get("IconPixmap") over real GDBus Properties interface.
        let icon_prop = call_async(
            &watcher_conn,
            &ctx,
            &item_bus,
            ITEM_PATH,
            "org.freedesktop.DBus.Properties",
            "Get",
            Some(&(ITEM_IFACE, "IconPixmap").to_variant()),
        );
        let pixmaps = icon_prop.child_value(0).as_variant().unwrap();
        assert_eq!(pixmaps.type_().as_str(), "a(iiay)");
        assert_eq!(pixmaps.n_children(), 2);
        let first_icon = pixmaps.child_value(0);
        assert_eq!((first_icon.child_get::<i32>(0), first_icon.child_get::<i32>(1)), (22, 22));
        assert_eq!(first_icon.child_value(2).n_children(), 22 * 22 * 4);

        // 2. Activate(x, y) over real GDBus invokes our activate callback.
        call_async(
            &watcher_conn,
            &ctx,
            &item_bus,
            ITEM_PATH,
            ITEM_IFACE,
            "Activate",
            Some(&(10i32, 20i32).to_variant()),
        );
        assert_eq!(activated.load(Ordering::SeqCst), 1);

        // 3. GetLayout(0, -1, []) over real GDBus returns the live menu tree.
        *menu_state() = MenuState {
            vm: "Running",
            running: vec![("abc123def".into(), "nginx".into(), Some("http://nginx.kiri.localhost".into()))],
        };
        let layout_reply = call_async(
            &watcher_conn,
            &ctx,
            &item_bus,
            MENU_PATH,
            MENU_IFACE,
            "GetLayout",
            Some(&(0i32, -1i32, Vec::<String>::new()).to_variant()),
        );
        assert_eq!(layout_reply.type_().as_str(), "(u(ia{sv}av))");
        let root = layout_reply.child_value(1);
        let children = root.child_value(2);
        assert!(children.n_children() >= 8);
        let container_node = children.child_value(2).as_variant().unwrap();
        assert_eq!(container_node.child_get::<i32>(0), ID_CONTAINER);

        // 4. Event(ID_START, "clicked", ...) sends Cmd::Start to the engine channel.
        let click_data = glib::Variant::from_variant(&0i32.to_variant());
        call_async(
            &watcher_conn,
            &ctx,
            &item_bus,
            MENU_PATH,
            MENU_IFACE,
            "Event",
            Some(&(ID_START, "clicked", click_data, 0u32).to_variant()),
        );
        assert!(matches!(rx.try_recv(), Ok(Cmd::Start)));

        // 5. Releasing the watcher bus name transitions tray_available() back to false.
        let lost_before = lost.load(Ordering::SeqCst);
        release_name();
        assert!(
            pump_until(&ctx, Duration::from_secs(5), || {
                !tray_available() && lost.load(Ordering::SeqCst) > lost_before
            }),
            "tray_available() must become false and the window come back when watcher vanishes"
        );
    }
}
