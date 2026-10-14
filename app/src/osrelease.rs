// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashMap;
use std::fs;

/// Minimal parser for an os-release file (KEY="value" lines, supporting
/// both quoted and unquoted values, plus comments).
#[derive(Debug, Default, Clone)]
pub struct OsRelease {
    pub id: Option<String>,
    pub id_like: Option<String>,
    pub version_id: Option<String>,
    pub sysext_level: Option<String>,
}

impl OsRelease {
    pub fn read(path: &str) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
        Ok(Self::parse(&text))
    }

    pub fn parse(text: &str) -> Self {
        let mut fields: HashMap<String, String> = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let v = v.trim().trim_matches('"').trim_matches('\'');
            fields.insert(k.trim().to_string(), v.to_string());
        }
        Self {
            id: fields.get("ID").cloned(),
            id_like: fields.get("ID_LIKE").cloned(),
            version_id: fields.get("VERSION_ID").cloned(),
            sysext_level: fields.get("SYSEXT_LEVEL").cloned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_fields() {
        let r = OsRelease::parse("ID=fedora\nVERSION_ID=\"44\"\n# comment\nSYSEXT_LEVEL=1\n");
        assert_eq!(r.id.as_deref(), Some("fedora"));
        assert_eq!(r.version_id.as_deref(), Some("44"));
        assert_eq!(r.sysext_level.as_deref(), Some("1"));
    }

    #[test]
    fn tolerates_missing_fields() {
        let r = OsRelease::parse("NAME=foo\n");
        assert_eq!(r.id, None);
        assert_eq!(r.version_id, None);
    }

    #[test]
    fn parses_id_like() {
        let r = OsRelease::parse("ID=fedora\nID_LIKE=\"rhel centos\"\n");
        assert_eq!(r.id_like.as_deref(), Some("rhel centos"));
    }
}
