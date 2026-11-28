//! Pull image's suggestions as they reach the page, from Docker Hub's answer
//! or from the hub.json cache, the same on every system (kiri-win includes
//! this file by `#[path]`). Every field has the type the page expects, so
//! nothing a remote answer or an edited cache holds reaches the page's HTML
//! as text where a number, a flag or a brand's icon goes: the icon is worked
//! out again from the name, never read back.

use serde_json::{json, Value};

/// A brand's icon for an image name (`brand` in ui/mod.rs and kiri-win's engine.rs).
pub type Brand = fn(&str) -> Option<[&'static str; 2]>;

/// One search row: Hub's (`star_count`, `is_official`) or the cache's
/// (`stars`, `official`, as the page gets it). None without a name.
pub fn search_row(r: &Value, brand: Brand) -> Option<Value> {
    let name = r["name"].as_str().filter(|n| !n.is_empty())?;
    let field = |hub: &str, ours: &str| if r.get(hub).is_some() { r[hub].clone() } else { r[ours].clone() };
    Some(json!({
        "name": name,
        "description": r["description"].as_str().unwrap_or_default(),
        "stars": field("star_count", "stars").as_u64().unwrap_or(0),
        "official": field("is_official", "official").as_bool().unwrap_or(false),
        "icon": brand(name),
    }))
}

/// A list of search rows.
pub fn search_rows(rows: &Value, brand: Brand) -> Value {
    Value::Array(rows.as_array().into_iter().flatten().filter_map(|r| search_row(r, brand)).collect())
}

/// A list of tags: strings only.
pub fn tags(items: &Value) -> Value {
    Value::Array(items.as_array().into_iter().flatten().filter(|t| t.is_string()).cloned().collect())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    fn brand(name: &str) -> Option<[&'static str; 2]> {
        (name == "postgres").then_some(["336791", "M0 0h1"])
    }

    #[test]
    fn stars_and_flags_are_numbers_and_flags_whatever_came() {
        let hub = json!([
            {"name": "postgres", "description": "db", "star_count": 14000, "is_official": true},
            {"name": "x/evil", "description": "<b>d</b>", "star_count": "<img src=x onerror=alert(1)>", "is_official": "yes"},
            {"name": "x/neg", "star_count": -3, "is_official": null},
            {"name": "x/float", "star_count": 1.5},
            {"name": "", "star_count": 1},
            {"star_count": 1},
            "not a row",
        ]);
        let rows = super::search_rows(&hub, brand);
        assert_eq!(
            rows,
            json!([
                {"name": "postgres", "description": "db", "stars": 14000, "official": true, "icon": ["336791", "M0 0h1"]},
                {"name": "x/evil", "description": "<b>d</b>", "stars": 0, "official": false, "icon": null},
                {"name": "x/neg", "description": "", "stars": 0, "official": false, "icon": null},
                {"name": "x/float", "description": "", "stars": 0, "official": false, "icon": null},
            ])
        );
    }

    /// What the cache gives back is checked as Hub's answer is, and the icon
    /// is the name's own, not the cache's.
    #[test]
    fn the_cache_is_read_as_untrusted_too() {
        let cache = json!([
            {"name": "postgres", "description": "db", "stars": 14000, "official": true, "icon": ["336791", "M0 0h1"]},
            {"name": "x/evil", "description": 5, "stars": "9<script>", "official": 1, "icon": ["\"><img src=x onerror=alert(1)>", "x"]},
        ]);
        let rows = super::search_rows(&cache, brand);
        assert_eq!(rows[0], json!({"name": "postgres", "description": "db", "stars": 14000, "official": true, "icon": ["336791", "M0 0h1"]}));
        assert_eq!(rows[1], json!({"name": "x/evil", "description": "", "stars": 0, "official": false, "icon": null}));
        assert_eq!(super::tags(&json!(["latest", 5, {"x": 1}, "17"])), json!(["latest", "17"]));
        assert_eq!(super::tags(&json!("latest")), json!([]));
    }
}
