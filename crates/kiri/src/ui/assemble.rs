//! The window's page as every system loads it: index.html with its icons
//! and the terminal emulator (xterm.js, vendored unmodified in `xterm/`)
//! spliced into their placeholders. The Mac and Linux window (crates/kiri)
//! and Windows (kiri-win includes this file) load the same string, and
//! scripts/ui-test.py builds it the same way.
//!
//! Its words: the English keys and the one language it opens in (the
//! `lang` setting's, or the system's for System; `lang::strings_js`), and the
//! system's languages and the saved pick (`lang::boot_js`). Another language
//! comes when the page switches to it: the page sends `langwords` and the
//! host evaluates `lang::words_js`.
//!
//! The page is loaded as a string, and WebView2's NavigateToString takes at
//! most 2 MB. With xterm.js and the keys it is about 1.4 M UTF-16 units, and
//! a language adds its words: 40 to 60 K units. All of them would be well
//! past the limit, which is why the page carries only one.

const ICONS_JS: &str = include_str!("icons.js");
const XTERM_CSS: &str = include_str!("xterm/xterm.css");
/// xterm.js 6.0.0 and its fit, search and web-links add-ons (UMD builds,
/// each defining a global), in the order they load.
const XTERM_JS: [&str; 4] = [include_str!("xterm/xterm.js"), include_str!("xterm/addon-fit.js"), include_str!("xterm/addon-search.js"), include_str!("xterm/addon-web-links.js")];

/// `index` (index.html) with everything spliced in, `lang` (the `lang`
/// setting) picking its language.
pub fn page(index: &str, lang: Option<&str>) -> String {
    let mut js = String::with_capacity(XTERM_JS.iter().map(|s| s.len() + 1).sum());
    for part in XTERM_JS {
        js.push_str(part);
        // Each ends in a source-map comment: the next must start on a line of its own.
        js.push('\n');
    }
    index
        .replacen("/*ICONS*/", ICONS_JS, 1)
        .replacen("/*XTERM_CSS*/", XTERM_CSS, 1)
        .replacen("/*XTERM_JS*/", &js, 1)
        .replacen("/*LANG*/", &super::lang::boot_js(lang), 1)
        .replacen("/*STRINGS*/{}", &super::lang::strings_js(super::lang::resolve(lang)), 1)
}

/// A page that only needs its words spliced in (kiri-win's setup page).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn words(page: &str, lang: Option<&str>) -> String {
    page.replacen("/*LANG*/", &super::lang::boot_js(lang), 1).replacen("/*STRINGS*/{}", &super::lang::strings_js(super::lang::resolve(lang)), 1)
}

#[cfg(test)]
mod tests {
    use super::super::lang;

    #[test]
    fn every_placeholder_is_filled_once_and_the_page_fits_webview2() {
        let units = |s: &str| s.encode_utf16().count();
        let page = super::page(include_str!("index.html"), None);
        for p in ["/*ICONS*/", "/*XTERM_CSS*/", "/*XTERM_JS*/", "/*LANG*/", "/*STRINGS*/"] {
            assert!(!page.contains(p), "{p} left in the page");
        }
        assert!(page.contains(".xterm-viewport"), "xterm.css missing");
        assert!(page.contains("window.KIRI_LANG = {") && page.contains(&lang::strings_js(lang::resolve(None))), "words missing");
        // Each language the page can open in carries the keys and that language
        // alone: the largest must stay well inside NavigateToString's 2 MB, with
        // room for the page to grow.
        let (mut worst, mut biggest) = (0, "");
        for (tag, _) in lang::FILES {
            let p = super::page(include_str!("index.html"), Some(tag));
            assert!(p.contains(&lang::strings_js(tag)), "{tag}'s words missing");
            for (other, _) in lang::FILES {
                assert!(other == tag || !p.contains(&format!("\"{other}\":[")), "{tag}'s page carries {other} too");
            }
            if units(&p) > worst {
                (worst, biggest) = (units(&p), tag);
            }
        }
        // NavigateToString's limit is 2 MB; 1.8 M keeps a margin, and the worst
        // case stays 200 K under that (a language's words are about 60 K).
        assert!(worst + 200_000 < 1_800_000, "the page in {biggest} is {worst} UTF-16 units");
        assert!(units(&page) <= worst);
        // Setup's page too.
        assert!(units(&super::words("/*LANG*/ /*STRINGS*/{}", Some(biggest))) < 200_000);
    }
}
