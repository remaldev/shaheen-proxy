use crate::ClientConfig;
use serde_json::Value;

/// Parses a proxy URL into components
///
/// # Parameters
/// - `url_str`: The proxy URL string to parse
///
/// # Returns
/// An `Option` containing a tuple of (protocol, username, password, host, port)
pub fn parse_proxy_url(url_str: &str) -> Option<(String, String, String, String, u16)> {
    let url = url::Url::parse(url_str).ok()?;

    let protocol = url.scheme().to_string();
    let username = url.username().to_string();
    let password = url.password().unwrap_or("").to_string();
    let host = url.host_str()?.to_string();
    let port = url.port_or_known_default()?;

    Some((protocol, username, password, host, port))
}

/// Processes a proxy option string, replacing template placeholders with real values.
///
/// # Behavior
/// - If the input string contains a template in `{}` (e.g. `"-{sessionId}"`),
///   it extracts the word inside and replaces it with the corresponding value
///   from `ProxySettings`.
/// - If no `{}` is found (e.g. `"-rotate"`), the string is appended unchanged.
/// - Returns `Some(true)` if the string was processed successfully,
///   `Some(false)` if the placeholder value was missing, or `None` if input was invalid.
///
/// # Examples
/// ```
/// // Case 1: template found and replaced
/// // input: "-{country}" → output: "-US"
///
/// // Case 2: no template, kept as is
/// // input: "-rotate" → output: "-rotate"
/// ```
///
/// # Parameters
/// - `opt`: JSON value containing the option string.
/// - `settings`: ProxySettings providing available field values.
/// - `opts`: mutable string where the processed result is appended.
///
/// # Returns
/// `Option<bool>` indicating processing success or failure.
pub fn replace_template_placeholder(opt: &Value, settings: &ClientConfig, opts: &mut String) -> Option<bool> {
    let s = opt.as_str()?;
    // Case 1: it's a template like "-{sessionId}"
    if let (Some(start), Some(end)) = (s.find('{'), s.find('}')) {
        let word = &s[start + 1..end];
        let value = match word {
            "country" => settings.country.as_deref()?,
            "state" => settings.state.as_deref()?,
            "city" => settings.city.as_deref()?,
            "session" => settings.sid.as_deref()?,
            "ttl" => &settings.ttl?.to_string(),
            "hostID" => &settings.host_id?.to_string(),
            _ => "",
        };

        if value.is_empty() {
            Some(false)
        } else {
            opts.push_str(&s.replace(&format!("{{{}}}", word), value));
            Some(true)
        }
    }
    // Case 2: not a template (no braces)
    else {
        opts.push_str(s);
        Some(true)
    }
}
