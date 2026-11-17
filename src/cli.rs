use std::collections::HashMap;

pub struct Args {
    pub positional: Vec<String>,
    pub flags: HashMap<String, String>,
}

impl Args {
    pub fn parse(raw: &[String]) -> Args {
        let mut out = Args {
            positional: Vec::new(),
            flags: HashMap::new(),
        };

        let mut i = 0;
        while i < raw.len() {
            let s = &raw[i];
            if s.len() > 1 && s.starts_with('-') {
                let name = s.trim_start_matches('-');
                match name.split_once('=') {
                    Some((k, v)) => {
                        out.flags.insert(k.to_string(), v.to_string());
                    }
                    None => {
                        let next_is_value = i + 1 < raw.len() && !raw[i + 1].starts_with('-');
                        if next_is_value {
                            out.flags.insert(name.to_string(), raw[i + 1].clone());
                            i += 1;
                        } else {
                            out.flags.insert(name.to_string(), "true".to_string());
                        }
                    }
                }
            } else {
                out.positional.push(s.clone());
            }
            i += 1;
        }
        out
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.flags.get(name).map(String::as_str)
    }

    pub fn string(&self, name: &str, default: &str) -> String {
        self.get(name).unwrap_or(default).to_string()
    }

    pub fn int(&self, name: &str, default: i64) -> Result<i64, String> {
        match self.get(name) {
            Some(v) => v
                .parse::<i64>()
                .map_err(|_| format!("-{name} needs a number, got {v:?}")),
            None => Ok(default),
        }
    }

    pub fn flag(&self, name: &str) -> bool {
        match self.get(name) {
            Some(v) => v != "false" && v != "no" && v != "0",
            None => false,
        }
    }
}
