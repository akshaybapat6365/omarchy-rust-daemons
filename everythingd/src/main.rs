use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

const PROTOCOL_VERSION: u32 = 1;
const PLUGIN_VERSION: &str = "0.1.0";
// UUIDv5 namespace: 40ad37f5-b488-50bc-b3ad-d310967b3fd2
const UI_ITEM_NAMESPACE_BYTES: [u8; 16] = [
    0x40, 0xad, 0x37, 0xf5, 0xb4, 0x88, 0x50, 0xbc, 0xb3, 0xad, 0xd3, 0x10, 0x96, 0x7b, 0x3f, 0xd2,
];
const TMUX_SEP: char = '\x1f';

const NVIM_QUERY_EXPR: &str = concat!(
    "luaeval('vim.json.encode({pid=vim.fn.getpid(),current=vim.api.nvim_get_current_buf(),",
    "cwd=vim.fn.getcwd(),",
    "terminal_title=(vim.o.title and vim.o.titlestring or \"\"),buffers=",
    "vim.tbl_map(function(b) return {bufnr=b.bufnr,name=b.name,changed=b.changed,",
    "loaded=b.loaded,listed=b.listed,windows=vim.fn.win_findbuf(b.bufnr),",
    "lastused=b.lastused,changedtick=vim.api.nvim_buf_get_changedtick(b.bufnr)} end,",
    "vim.fn.getbufinfo({buflisted=1}))})')"
);

const GROUP_ORDER: &[&str] = &[
    "window",
    "browser-tab",
    "app-tab",
    "terminal-tab",
    "terminal-pane",
    "herdr-agent",
    "herdr-workspace",
    "herdr-tab",
    "herdr-pane",
    "herdr-session",
    "tmux-session",
    "tmux-window",
    "tmux-pane",
    "neovim-buffer",
];

// ---------------------------------------------------------------- Encoding helpers

fn identity_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(&mut out, "%{:02X}", b);
        }
    }
    out
}

fn stable_id(provider: &str, parts: &[String]) -> String {
    let mut out = String::with_capacity(provider.len() + 1 + parts.len() * 12);
    out.push_str(provider);
    out.push(':');
    for (idx, p) in parts.iter().enumerate() {
        if idx > 0 {
            out.push('/');
        }
        out.push_str(&identity_component(p));
    }
    out
}

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(((data.len() + 9 + 63) / 64) * 64);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }
    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

fn thing_ui_uuid(provider: &str, kind: &str, id: &str) -> String {
    let traits = serde_json::to_string(&[provider, kind, id]).unwrap_or_default();
    let mut buf = Vec::with_capacity(16 + traits.len());
    buf.extend_from_slice(&UI_ITEM_NAMESPACE_BYTES);
    buf.extend_from_slice(traits.as_bytes());
    let hash = sha1(&buf);
    let mut u = [0u8; 16];
    u.copy_from_slice(&hash[..16]);
    u[6] = (u[6] & 0x0f) | 0x50; // Version 5
    u[8] = (u[8] & 0x3f) | 0x80; // RFC 4122 variant
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]
    )
}

fn b64url_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((input.len() * 4 + 2) / 3);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    match input.len() - i {
        1 => {
            let n = (input[i] as u32) << 16;
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
        }
        2 => {
            let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        }
        _ => {}
    }
    out
}

fn b64url_decode(input: &str) -> Result<Vec<u8>, String> {
    let val = |c: u8| -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err("malformed activation token".to_string()),
        }
    };
    let bytes = input.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let a = val(bytes[i])? as u32;
        let b = val(bytes[i + 1])? as u32;
        let c = val(bytes[i + 2])? as u32;
        let d = val(bytes[i + 3])? as u32;
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push(((n >> 16) & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
        out.push((n & 0xff) as u8);
        i += 4;
    }
    match bytes.len() - i {
        0 => {}
        2 => {
            let a = val(bytes[i])? as u32;
            let b = val(bytes[i + 1])? as u32;
            let n = (a << 18) | (b << 12);
            out.push(((n >> 16) & 0xff) as u8);
        }
        3 => {
            let a = val(bytes[i])? as u32;
            let b = val(bytes[i + 1])? as u32;
            let c = val(bytes[i + 2])? as u32;
            let n = (a << 18) | (b << 12) | (c << 6);
            out.push(((n >> 16) & 0xff) as u8);
            out.push(((n >> 8) & 0xff) as u8);
        }
        _ => return Err("malformed activation token".to_string()),
    }
    Ok(out)
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(values.len());
    let mut seen = HashSet::with_capacity(values.len());
    for v in values {
        let t = v.trim();
        if !t.is_empty() && seen.insert(t.to_string()) {
            out.push(t.to_string());
        }
    }
    out
}

fn canonical_path(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let expanded = if value == "~" {
        std::env::var("HOME").unwrap_or_else(|_| value.to_string())
    } else if let Some(rest) = value.strip_prefix("~/") {
        format!(
            "{}/{}",
            std::env::var("HOME").unwrap_or_default(),
            rest
        )
    } else {
        value.to_string()
    };
    fs::canonicalize(&expanded)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or(expanded)
}

fn normalized_address(value: &str) -> String {
    let addr = value.trim().to_ascii_lowercase();
    if !addr.is_empty() && !addr.starts_with("0x") {
        format!("0x{}", addr)
    } else {
        addr
    }
}

fn is_valid_hypr_address(addr: &str) -> bool {
    addr.len() > 2
        && addr.starts_with("0x")
        && addr[2..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_valid_tmux_native_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    bytes.len() >= 2
        && matches!(bytes[0], b'$' | b'@' | b'%')
        && bytes[1..].iter().all(|b| b.is_ascii_digit())
}

fn is_valid_herdr_native_id(id: &str) -> bool {
    !id.trim().is_empty() && !id.bytes().any(|b| matches!(b, 0 | b'\n' | b'\r'))
}

fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

fn current_username() -> String {
    let uid = current_uid();
    unsafe {
        let pw = libc::getpwuid(uid);
        if !pw.is_null() && !(*pw).pw_name.is_null() {
            return std::ffi::CStr::from_ptr((*pw).pw_name)
                .to_string_lossy()
                .into_owned();
        }
    }
    uid.to_string()
}

fn runtime_dir() -> String {
    std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("/run/user/{}", current_uid()))
}

// ---------------------------------------------------------------- Model & Tokens

#[derive(Clone, Debug)]
struct Thing {
    id: String,
    kind: String,
    provider: String,
    title: String,
    icon_hints: Vec<String>,
    context: String,
    search_terms: Vec<String>,
    parent_id: String,
    badges: Vec<String>,
    active: bool,
    recency: f64,
    activation: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PublicThing {
    id: String,
    #[serde(rename = "uiUuid")]
    ui_uuid: String,
    kind: String,
    provider: String,
    title: String,
    #[serde(rename = "iconHints")]
    icon_hints: Vec<String>,
    context: String,
    #[serde(rename = "searchTerms")]
    search_terms: Vec<String>,
    #[serde(rename = "parentId")]
    parent_id: String,
    badges: Vec<String>,
    active: bool,
    recency: f64,
    #[serde(rename = "activationToken")]
    activation_token: String,
}

impl Thing {
    fn normalize(mut self) -> Self {
        let t = self.title.trim();
        self.title = if t.is_empty() {
            "Untitled".to_string()
        } else {
            t.to_string()
        };
        self.icon_hints = unique_strings(self.icon_hints);
        self.context = self.context.trim().to_string();
        self.search_terms = unique_strings(self.search_terms);
        self.badges = unique_strings(self.badges);
        self
    }

    fn to_public(&self, token: String) -> PublicThing {
        PublicThing {
            ui_uuid: thing_ui_uuid(&self.provider, &self.kind, &self.id),
            id: self.id.clone(),
            kind: self.kind.clone(),
            provider: self.provider.clone(),
            title: self.title.clone(),
            icon_hints: self.icon_hints.clone(),
            context: self.context.clone(),
            search_terms: self.search_terms.clone(),
            parent_id: self.parent_id.clone(),
            badges: self.badges.clone(),
            active: self.active,
            recency: self.recency,
            activation_token: token,
        }
    }
}

fn dedupe_things(items: Vec<Thing>) -> Vec<Thing> {
    let mut out: Vec<Thing> = Vec::with_capacity(items.len());
    let mut positions: HashMap<String, usize> = HashMap::with_capacity(items.len());
    let mut collision_counts: HashMap<String, usize> = HashMap::new();

    for raw in items {
        let item = raw.normalize();
        if let Some(&pos) = positions.get(&item.id) {
            let existing = &mut out[pos];
            if existing.activation == item.activation && existing.kind == item.kind {
                let mut ih = existing.icon_hints.clone();
                ih.extend(item.icon_hints);
                existing.icon_hints = unique_strings(ih);
                let mut st = existing.search_terms.clone();
                st.extend(item.search_terms);
                existing.search_terms = unique_strings(st);
                let mut bg = existing.badges.clone();
                bg.extend(item.badges);
                existing.badges = unique_strings(bg);
                existing.active = existing.active || item.active;
                existing.recency = existing.recency.max(item.recency);
                continue;
            }
            let mut count = collision_counts.get(&item.id).copied().unwrap_or(1) + 1;
            let mut cid;
            loop {
                cid = stable_id(
                    &item.provider,
                    &["collision".to_string(), item.id.clone(), count.to_string()],
                );
                if !positions.contains_key(&cid) {
                    break;
                }
                count += 1;
            }
            collision_counts.insert(item.id.clone(), count);
            positions.insert(cid.clone(), out.len());
            let mut cloned = item;
            cloned.id = cid;
            out.push(cloned);
        } else {
            positions.insert(item.id.clone(), out.len());
            out.push(item);
        }
    }
    out
}

struct TokenCodec {
    secret: [u8; 32],
}

impl TokenCodec {
    fn new() -> Self {
        let mut secret = [0u8; 32];
        if let Ok(mut f) = File::open("/dev/urandom") {
            let _ = f.read_exact(&mut secret);
        } else {
            let t = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let pid = std::process::id() as u128;
            let bytes = (t ^ (pid << 64)).to_le_bytes();
            secret[..16].copy_from_slice(&bytes);
            secret[16..].copy_from_slice(&bytes);
        }
        Self { secret }
    }

    fn encode(&self, payload: &Value) -> String {
        let raw = serde_json::to_vec(payload).unwrap_or_default();
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC key");
        mac.update(&raw);
        let sig = mac.finalize().into_bytes();
        format!("v1.{}.{}", b64url_encode(&raw), b64url_encode(&sig))
    }

    fn decode(&self, token: &str) -> Result<Value, String> {
        let mut parts = token.splitn(3, '.');
        let (Some(prefix), Some(body), Some(sig_b64)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err("malformed activation token".to_string());
        };
        if prefix != "v1" {
            return Err("unsupported activation token version".to_string());
        }
        let raw = b64url_decode(body)?;
        let supplied = b64url_decode(sig_b64)?;
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC key");
        mac.update(&raw);
        if mac.verify_slice(&supplied).is_err() {
            return Err("activation token authentication failed".to_string());
        }
        let val: Value = serde_json::from_slice(&raw)
            .map_err(|_| "activation token payload is invalid".to_string())?;
        if !val.is_object() {
            return Err("activation token payload is not an object".to_string());
        }
        Ok(val)
    }
}

#[derive(Clone)]
struct PublishedThing {
    thing: Thing,
    token: String,
    generation: u64,
}

struct SnapshotRegistry {
    codec: TokenCodec,
    generations: HashMap<String, u64>,
    providers: BTreeMap<String, Vec<PublishedThing>>,
}

impl SnapshotRegistry {
    fn new() -> Self {
        Self {
            codec: TokenCodec::new(),
            generations: HashMap::new(),
            providers: BTreeMap::new(),
        }
    }

    fn publish(&mut self, provider: &str, items: Vec<Thing>) -> Vec<PublicThing> {
        let generation = self.generations.get(provider).copied().unwrap_or(0) + 1;
        self.generations.insert(provider.to_string(), generation);
        let deduped = dedupe_things(items);
        let mut published = Vec::with_capacity(deduped.len());
        let mut public = Vec::with_capacity(deduped.len());
        for thing in deduped {
            let payload = json!({
                "activation": thing.activation,
                "generation": generation,
                "id": thing.id,
                "provider": provider,
            });
            let token = self.codec.encode(&payload);
            public.push(thing.to_public(token.clone()));
            published.push(PublishedThing {
                thing,
                token,
                generation,
            });
        }
        self.providers.insert(provider.to_string(), published);
        public
    }

    fn decode_reference(&self, item_id: &str, token: &str) -> Result<Value, String> {
        let payload = self.codec.decode(token)?;
        if payload.get("id").and_then(|v| v.as_str()) != Some(item_id) {
            return Err("activation token does not belong to this item".to_string());
        }
        let provider = payload
            .get("provider")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if provider.is_empty() {
            return Err("activation token has no provider".to_string());
        }
        Ok(payload)
    }

    fn current(&self, provider: &str, item_id: &str) -> Option<PublishedThing> {
        self.providers
            .get(provider)?
            .iter()
            .find(|p| p.thing.id == item_id)
            .cloned()
    }

    fn token_is_current(&self, payload: &Value) -> bool {
        let provider = payload.get("provider").and_then(|v| v.as_str()).unwrap_or("");
        let item_id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let generation = payload.get("generation").and_then(|v| v.as_u64()).unwrap_or(0);
        self.current(provider, item_id)
            .map(|row| row.generation == generation)
            .unwrap_or(false)
    }

    fn all_public(&self) -> Vec<PublicThing> {
        let mut out = Vec::new();
        for rows in self.providers.values() {
            for p in rows {
                out.push(p.thing.to_public(p.token.clone()));
            }
        }
        out
    }

    fn providers_map(&self) -> BTreeMap<String, Vec<PublicThing>> {
        let mut map = BTreeMap::new();
        for (k, rows) in &self.providers {
            map.insert(
                k.clone(),
                rows.iter()
                    .map(|p| p.thing.to_public(p.token.clone()))
                    .collect(),
            );
        }
        map
    }
}

// ---------------------------------------------------------------- Fast /proc table

fn proc_cwd(pid: i32) -> String {
    if pid <= 0 {
        return String::new();
    }
    fs::read_link(format!("/proc/{}/cwd", pid))
        .ok()
        .and_then(|p| fs::canonicalize(&p).ok().or(Some(p)))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[derive(Clone, Debug)]
struct ProcInfo {
    pid: i32,
    ppid: i32,
    start_time: String,
    comm: String,
    argv: Vec<String>,
}

#[derive(Clone)]
struct ProcTable {
    uid: u32,
    procs: HashMap<i32, ProcInfo>,
}

fn process_birth(pid: i32) -> String {
    if pid <= 0 {
        return "unknown".to_string();
    }
    let path = format!("/proc/{}/stat", pid);
    let Ok(mut f) = File::open(&path) else {
        return "unknown".to_string();
    };
    let mut buf = [0u8; 1024];
    let Ok(n) = f.read(&mut buf) else {
        return "unknown".to_string();
    };
    let Ok(s) = std::str::from_utf8(&buf[..n]) else {
        return "unknown".to_string();
    };
    let Some(rp) = s.rfind(')') else {
        return "unknown".to_string();
    };
    s.get(rp + 2..)
        .and_then(|rest| rest.split_ascii_whitespace().nth(19))
        .map(|v| v.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

impl ProcTable {
    fn read() -> Self {
        let uid = current_uid();
        let mut procs = HashMap::with_capacity(256);
        let Ok(rd) = fs::read_dir("/proc") else {
            return Self { uid, procs };
        };
        let mut stat_buf = [0u8; 1024];
        let mut cmd_buf = [0u8; 2048];
        for entry in rd.flatten() {
            let fname = entry.file_name();
            let Some(name_s) = fname.to_str() else {
                continue;
            };
            if !name_s.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let Ok(pid) = name_s.parse::<i32>() else {
                continue;
            };
            let stat_path = format!("/proc/{}/stat", pid);
            let Ok(mut f) = File::open(&stat_path) else {
                continue;
            };
            if f.metadata().map(|m| m.uid()).unwrap_or(u32::MAX) != uid {
                continue;
            }
            let Ok(n) = f.read(&mut stat_buf) else {
                continue;
            };
            let Ok(s) = std::str::from_utf8(&stat_buf[..n]) else {
                continue;
            };
            let (Some(lp), Some(rp)) = (s.find('('), s.rfind(')')) else {
                continue;
            };
            if rp <= lp || rp + 2 > s.len() {
                continue;
            }
            let comm = s[lp + 1..rp].to_string();
            let mut fields = s[rp + 2..].split_ascii_whitespace();
            let _state = fields.next();
            let Some(ppid) = fields.next().and_then(|v| v.parse::<i32>().ok()) else {
                continue;
            };
            let Some(start_time) = fields.nth(17).map(|v| v.to_string()) else {
                continue;
            };

            let mut argv = Vec::new();
            if let Ok(mut cf) = File::open(format!("/proc/{}/cmdline", pid)) {
                if let Ok(cn) = cf.read(&mut cmd_buf) {
                    for part in cmd_buf[..cn].split(|&b| b == 0) {
                        if !part.is_empty() {
                            argv.push(String::from_utf8_lossy(part).into_owned());
                        }
                    }
                }
            }
            procs.insert(
                pid,
                ProcInfo {
                    pid,
                    ppid,
                    start_time,
                    comm,
                    argv,
                },
            );
        }
        Self { uid, procs }
    }

    fn get(&self, pid: i32) -> Option<&ProcInfo> {
        self.procs.get(&pid)
    }

    fn ancestors(&self, pid: i32) -> Vec<&ProcInfo> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut cur = self.get(pid);
        while let Some(p) = cur {
            if !seen.insert(p.pid) || out.len() >= 128 {
                break;
            }
            out.push(p);
            cur = self.get(p.ppid);
        }
        out
    }

    fn ancestor_pid_in(&self, pid: i32, candidates: &HashSet<i32>) -> Option<i32> {
        self.ancestors(pid)
            .into_iter()
            .find(|p| candidates.contains(&p.pid))
            .map(|p| p.pid)
    }

    fn is_descendant(&self, pid: i32, ancestor: i32) -> bool {
        self.ancestors(pid).into_iter().any(|p| p.pid == ancestor)
    }

    fn named(&self, names: &[&str]) -> Vec<&ProcInfo> {
        self.procs
            .values()
            .filter(|p| {
                let cl = p.comm.to_ascii_lowercase();
                if names.iter().any(|&n| cl == n) {
                    return true;
                }
                if let Some(arg0) = p.argv.first() {
                    let base = Path::new(arg0)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    return names.iter().any(|&n| base == n);
                }
                false
            })
            .collect()
    }

    fn environment(&self, pid: i32, wanted: &[&str]) -> HashMap<String, String> {
        let mut out = HashMap::new();
        if self.get(pid).is_none() {
            return out;
        }
        let path = format!("/proc/{}/environ", pid);
        let Ok(f) = File::open(&path) else {
            return out;
        };
        if f.metadata().map(|m| m.uid()).unwrap_or(u32::MAX) != self.uid {
            return out;
        }
        let mut buf = Vec::new();
        if f.take(256 * 1024 + 1).read_to_end(&mut buf).is_err() || buf.len() > 256 * 1024 {
            return out;
        }
        for entry in buf.split(|&b| b == 0) {
            if let Some(eq) = entry.iter().position(|&b| b == b'=') {
                let k = String::from_utf8_lossy(&entry[..eq]);
                if wanted.iter().any(|&w| w == k.as_ref()) {
                    let v = String::from_utf8_lossy(&entry[eq + 1..]).into_owned();
                    out.insert(k.into_owned(), v);
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------- Direct Unix Socket IPC

fn latest_hypr_socket() -> Result<PathBuf, String> {
    let hypr_root = PathBuf::from(runtime_dir()).join("hypr");
    let mut best: Option<(SystemTime, PathBuf)> = None;
    if let Ok(rd) = fs::read_dir(&hypr_root) {
        for entry in rd.flatten() {
            let sock = entry.path().join(".socket.sock");
            if sock.exists() {
                let mtime = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(UNIX_EPOCH);
                if best.as_ref().map(|(t, _)| mtime > *t).unwrap_or(true) {
                    best = Some((mtime, sock));
                }
            }
        }
    }
    if let Some((_, sock)) = best {
        return Ok(sock);
    }
    if let Ok(sig) = std::env::var("HYPRLAND_INSTANCE_SIGNATURE") {
        let sock = hypr_root.join(sig).join(".socket.sock");
        if sock.exists() {
            return Ok(sock);
        }
    }
    Err("Hyprland socket not found".to_string())
}

fn hypr_ipc(cmd: &str) -> Result<String, String> {
    let sock = latest_hypr_socket()?;
    let mut stream = UnixStream::connect(&sock).map_err(|e| format!("Hyprland IPC failed: {}", e))?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1000)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    stream
        .write_all(cmd.as_bytes())
        .map_err(|e| format!("Hyprland IPC write failed: {}", e))?;
    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .map_err(|e| format!("Hyprland IPC read failed: {}", e))?;
    Ok(resp)
}

fn hypr_focus_address(address: &str) -> Result<(), String> {
    let target = normalized_address(address);
    if !is_valid_hypr_address(&target) {
        return Err("refusing an invalid Hyprland address".to_string());
    }
    let expr = format!(
        "dispatch hl.dsp.focus({{ window = {} }})",
        serde_json::to_string(&format!("address:{}", target)).unwrap_or_default()
    );
    let reply = hypr_ipc(&expr)?;
    let trimmed = reply.trim();
    if trimmed.is_empty() || trimmed == "ok" {
        return Ok(());
    }
    // Fallback to standard focuswindow dispatcher if Lua expression isn't active
    let fb = hypr_ipc(&format!("dispatch focuswindow address:{}", target))?;
    let fb_trimmed = fb.trim();
    if fb_trimmed.is_empty() || fb_trimmed == "ok" {
        Ok(())
    } else {
        Err(if !trimmed.is_empty() {
            trimmed.to_string()
        } else {
            "Hyprland focus failed".to_string()
        })
    }
}

fn unix_json_line_request(socket_path: &str, request: &Value, timeout_ms: u64) -> Result<Value, String> {
    let mut stream =
        UnixStream::connect(socket_path).map_err(|e| format!("socket connect failed: {}", e))?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)));
    let mut payload = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    payload.push(b'\n');
    stream
        .write_all(&payload)
        .map_err(|e| format!("socket write failed: {}", e))?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .map_err(|e| format!("socket read failed: {}", e))?;
    if n == 0 || line.len() > 8 * 1024 * 1024 {
        return Err("socket returned an empty or oversized response".to_string());
    }
    let val: Value =
        serde_json::from_str(&line).map_err(|_| "socket response is invalid JSON".to_string())?;
    if !val.is_object() {
        return Err("socket response is not a JSON object".to_string());
    }
    Ok(val)
}

fn kitty_socket_cmd(socket_path: &str, cmd_json: &Value) -> Result<Value, String> {
    let mut stream =
        UnixStream::connect(socket_path).map_err(|e| format!("Kitty socket error: {}", e))?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1200)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(600)));
    let mut frame = Vec::with_capacity(128);
    frame.extend_from_slice(b"\x1bP@kitty-cmd");
    frame.extend_from_slice(&serde_json::to_vec(cmd_json).unwrap_or_default());
    frame.extend_from_slice(b"\x1b\\");
    stream
        .write_all(&frame)
        .map_err(|e| format!("Kitty socket write failed: {}", e))?;

    let mut buf = Vec::with_capacity(16384);
    let mut chunk = [0u8; 16384];
    loop {
        let n = stream
            .read(&mut chunk)
            .map_err(|e| format!("Kitty socket read failed: {}", e))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(2).any(|w| w == b"\x1b\\") || buf.len() > 8 * 1024 * 1024 {
            break;
        }
    }
    let prefix = b"\x1bP@kitty-cmd";
    if !buf.starts_with(prefix) {
        return Err("Kitty socket returned unexpected framing".to_string());
    }
    let end = buf
        .windows(2)
        .rposition(|w| w == b"\x1b\\")
        .ok_or("Kitty response truncated")?;
    let body = &buf[prefix.len()..end];
    serde_json::from_slice(body).map_err(|_| "Kitty returned invalid JSON".to_string())
}

fn spawn_detached(argv: &[String]) -> Result<(), String> {
    if argv.is_empty() {
        return Err("empty command".to_string());
    }
    unsafe {
        Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .pre_exec(|| {
                libc::setsid();
                Ok(())
            })
            .spawn()
            .map_err(|e| format!("spawn {} failed: {}", argv[0], e))?;
    }
    Ok(())
}

// ---------------------------------------------------------------- Provider Metadata

#[derive(Clone, Default)]
struct HyprClientMeta {
    address: String,
    pid: i32,
    title: String,
    item_id: String,
}

#[derive(Clone)]
struct SurfaceMeta {
    provider: String,
    item_id: String,
    pid: i32,
    title: String,
    cwd: String,
    activation: Value,
}

#[derive(Clone)]
struct TmuxPaneMeta {
    item_id: String,
    pane_pid: i32,
    activation: Value,
}

#[derive(Clone)]
struct HerdrPaneMeta {
    item_id: String,
    socket: String,
    server_pid: i32,
    pane_id: String,
    cwd: String,
    activation: Value,
}

#[derive(Clone)]
struct HerdrSessionMeta {
    server_pid: i32,
}

#[derive(Clone, Default)]
struct ProviderMeta {
    hypr_clients: Vec<HyprClientMeta>,
    kitty_surfaces: Vec<SurfaceMeta>,
    tmux_panes: Vec<TmuxPaneMeta>,
    herdr_panes: Vec<HerdrPaneMeta>,
    herdr_sessions: Vec<HerdrSessionMeta>,
}

impl ProviderMeta {
    fn clients_for_pid(&self, pid: i32) -> Vec<&HyprClientMeta> {
        self.hypr_clients.iter().filter(|c| c.pid == pid).collect()
    }

    fn client_by_address(&self, addr: &str) -> Option<&HyprClientMeta> {
        let wanted = normalized_address(addr);
        self.hypr_clients.iter().find(|c| c.address == wanted)
    }

    fn route_for_process(&self, procs: &ProcTable, pid: i32, title: &str, cwd: &str) -> Option<(String, Value)> {
        let wanted_cwd = canonical_path(cwd);
        let ancestors = procs.ancestors(pid);
        let anc_pids: HashSet<i32> = ancestors.iter().map(|p| p.pid).collect();

        let kitty_matches: Vec<&SurfaceMeta> = self
            .kitty_surfaces
            .iter()
            .filter(|s| anc_pids.contains(&s.pid))
            .collect();
        if !kitty_matches.is_empty() {
            if kitty_matches.len() == 1 {
                return Some((kitty_matches[0].provider.clone(), kitty_matches[0].activation.clone()));
            }
            let exact: Vec<&SurfaceMeta> = kitty_matches
                .into_iter()
                .filter(|s| !title.is_empty() && s.title == title && !wanted_cwd.is_empty() && canonical_path(&s.cwd) == wanted_cwd)
                .collect();
            if exact.len() == 1 {
                return Some((exact[0].provider.clone(), exact[0].activation.clone()));
            }
            return None;
        }

        if ancestors.iter().any(|p| {
            let cl = p.comm.to_ascii_lowercase();
            cl == "kitty"
                || cl == "ghostty"
                || p.argv
                    .first()
                    .and_then(|a| Path::new(a).file_name().and_then(|s| s.to_str()))
                    .map(|b| b.eq_ignore_ascii_case("kitty") || b.eq_ignore_ascii_case("ghostty"))
                    .unwrap_or(false)
        }) {
            return None;
        }

        let managed: HashSet<i32> = self.hypr_clients.iter().map(|c| c.pid).collect();
        let anc = procs.ancestor_pid_in(pid, &managed)?;
        let clients = self.clients_for_pid(anc);
        if clients.len() != 1 {
            return None;
        }
        let c = clients[0];
        Some((
            "hyprland".to_string(),
            json!({
                "address": c.address,
                "pid": c.pid,
                "birth": process_birth(c.pid),
            }),
        ))
    }
}

struct ProviderScan {
    items: Vec<Thing>,
    warnings: Vec<String>,
}

// ---------------------------------------------------------------- Provider 1: Hyprland

fn scan_hyprland(procs: Option<&ProcTable>) -> Result<(ProviderScan, Vec<HyprClientMeta>), String> {
    let raw_json = hypr_ipc("j/clients")?;
    let clients: Vec<Value> = serde_json::from_str(&raw_json)
        .map_err(|_| "Hyprland returned invalid client JSON".to_string())?;

    let mut items = Vec::with_capacity(clients.len());
    let mut meta_clients = Vec::with_capacity(clients.len());

    for client in clients {
        if !client.is_object() {
            continue;
        }
        if client.get("mapped").and_then(|v| v.as_bool()) == Some(false) {
            continue;
        }
        let addr_raw = client.get("address").and_then(|v| v.as_str()).unwrap_or("");
        let address = normalized_address(addr_raw);
        if !is_valid_hypr_address(&address) {
            continue;
        }
        let pid = client.get("pid").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
        let birth = procs
            .and_then(|pt| pt.get(pid))
            .map(|p| p.start_time.clone())
            .unwrap_or_else(|| process_birth(pid));
        let cls = client.get("class").and_then(|v| v.as_str()).unwrap_or("");
        let init_cls = client
            .get("initialClass")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let init_title = client
            .get("initialTitle")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let app_class = if !cls.is_empty() {
            cls
        } else if !init_cls.is_empty() {
            init_cls
        } else {
            "Application"
        };
        let raw_title = client.get("title").and_then(|v| v.as_str()).unwrap_or("");
        let title = if !raw_title.is_empty() {
            raw_title
        } else if !init_title.is_empty() {
            init_title
        } else {
            app_class
        };

        let mut icon_hints = Vec::new();
        for key in ["icon", "class", "initialClass", "initialTitle"] {
            if let Some(s) = client.get(key).and_then(|v| v.as_str()) {
                if !s.trim().is_empty() {
                    icon_hints.push(s.to_string());
                }
            }
        }
        let ws_obj = client.get("workspace").and_then(|v| v.as_object());
        let ws_name = ws_obj
            .and_then(|w| {
                w.get("name")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .or_else(|| w.get("id").and_then(|v| v.as_i64()).map(|n| n.to_string()))
            })
            .unwrap_or_else(|| "unknown".to_string());

        let mut badges = vec!["Window".to_string(), format!("Workspace {}", ws_name)];
        let hidden = client.get("hidden").and_then(|v| v.as_bool()) == Some(true);
        if hidden {
            badges.push("Hidden".to_string());
        }
        let grouped = client
            .get("grouped")
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);
        if grouped {
            badges.push("Group".to_string());
        }
        if ws_name.starts_with("special:") {
            badges.push("Scratchpad".to_string());
        }
        let focus_history = client
            .get("focusHistoryID")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let item_id = stable_id(
            "hyprland",
            &[address.clone(), pid.to_string(), birth.clone()],
        );
        let recency = (-4000i64).max(4000 - focus_history * 100) as f64;

        items.push(Thing {
            id: item_id.clone(),
            kind: "window".to_string(),
            provider: "Hyprland".to_string(),
            title: title.to_string(),
            icon_hints,
            context: format!("{} · workspace {}", app_class, ws_name),
            search_terms: vec![
                app_class.to_string(),
                init_cls.to_string(),
                init_title.to_string(),
                ws_name.clone(),
            ],
            parent_id: String::new(),
            badges,
            active: focus_history == 0 && !hidden,
            recency,
            activation: json!({
                "address": address,
                "pid": pid,
                "birth": birth,
            }),
        });

        meta_clients.push(HyprClientMeta {
            address,
            pid,
            title: title.to_string(),
            item_id,
        });
    }

    Ok((
        ProviderScan {
            items,
            warnings: Vec::new(),
        },
        meta_clients,
    ))
}

// ---------------------------------------------------------------- Provider 2: Kitty (Direct Unix Socket!)

fn scan_kitty(procs: &ProcTable, hypr_clients: &[HyprClientMeta]) -> (ProviderScan, Vec<SurfaceMeta>) {
    let mut items = Vec::new();
    let mut warnings = Vec::new();
    let mut surfaces = Vec::new();
    let uid = current_uid();
    let runtime = runtime_dir();

    let mut sockets: Vec<(String, i32, String, u64, u64)> = Vec::new();
    if let Ok(rd) = fs::read_dir(&runtime) {
        for entry in rd.flatten() {
            let fname = entry.file_name();
            let Some(name) = fname.to_str() else { continue };
            let Some(pid_str) = name.strip_prefix("omarchy-kitty-") else {
                continue;
            };
            if pid_str.is_empty() || !pid_str.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let Ok(pid) = pid_str.parse::<i32>() else {
                continue;
            };
            let Some(proc_info) = procs.get(pid) else {
                continue;
            };
            let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if meta.uid() != uid || !meta.file_type().is_socket() {
                continue;
            }
            let full_cmd = format!("{} {}", proc_info.comm, proc_info.argv.join(" ")).to_ascii_lowercase();
            if !full_cmd.contains("kitty") {
                continue;
            }
            sockets.push((
                entry.path().to_string_lossy().into_owned(),
                pid,
                proc_info.start_time.clone(),
                meta.dev(),
                meta.ino(),
            ));
        }
    }
    sockets.sort_by(|a, b| a.0.cmp(&b.0));

    for (sock_path, pid, birth, sdev, sino) in sockets {
        let resp = match kitty_socket_cmd(
            &sock_path,
            &json!({"cmd": "ls", "version": [0, 26, 0], "no_response": false}),
        ) {
            Ok(v) => v,
            Err(_) => {
                warnings.push(format!(
                    "Kitty socket {} is stale",
                    Path::new(&sock_path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("kitty")
                ));
                continue;
            }
        };
        if resp.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            continue;
        }
        let os_windows: Vec<Value> = match resp.get("data") {
            Some(Value::String(s)) => serde_json::from_str(s).unwrap_or_default(),
            Some(Value::Array(a)) => a.clone(),
            _ => continue,
        };

        for os_win in os_windows {
            let os_id = os_win.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
            let os_focused = os_win
                .get("is_focused")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let tabs = os_win
                .get("tabs")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            // Match host Hyprland client
            let pid_clients: Vec<&HyprClientMeta> =
                hypr_clients.iter().filter(|c| c.pid == pid).collect();
            let host: Option<&HyprClientMeta> = if pid_clients.len() == 1 {
                Some(pid_clients[0])
            } else {
                let focused_tab = tabs
                    .iter()
                    .find(|t| t.get("is_focused").and_then(|v| v.as_bool()) == Some(true))
                    .or_else(|| tabs.first());
                let ttitle = focused_tab
                    .and_then(|t| t.get("title").and_then(|v| v.as_str()))
                    .unwrap_or("");
                let matched: Vec<&HyprClientMeta> = pid_clients
                    .into_iter()
                    .filter(|c| c.title == ttitle)
                    .collect();
                if matched.len() == 1 {
                    Some(matched[0])
                } else {
                    None
                }
            };
            let parent_window = host.map(|h| h.item_id.clone()).unwrap_or_default();
            let host_address = host.map(|h| h.address.clone()).unwrap_or_default();

            for tab in tabs {
                let tab_id = tab.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                if tab_id <= 0 {
                    continue;
                }
                let windows = tab
                    .get("windows")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut tab_title = tab
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if tab_title.is_empty() {
                    tab_title = windows
                        .first()
                        .and_then(|w| w.get("title").and_then(|v| v.as_str()))
                        .unwrap_or("Kitty tab")
                        .to_string();
                }
                let cwds: Vec<String> = windows
                    .iter()
                    .filter_map(|w| w.get("cwd").and_then(|v| v.as_str()))
                    .map(canonical_path)
                    .filter(|s| !s.is_empty())
                    .collect();
                let tab_ctx = if !cwds.is_empty() && cwds.iter().all(|c| c == &cwds[0]) {
                    cwds[0].clone()
                } else {
                    "Kitty".to_string()
                };
                let tab_thing_id = stable_id(
                    "kitty",
                    &[
                        sock_path.clone(),
                        sdev.to_string(),
                        sino.to_string(),
                        pid.to_string(),
                        birth.clone(),
                        os_id.to_string(),
                        "tab".to_string(),
                        tab_id.to_string(),
                    ],
                );
                let tab_active = os_focused
                    && tab
                        .get("is_focused")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                items.push(Thing {
                    id: tab_thing_id.clone(),
                    kind: "terminal-tab".to_string(),
                    provider: "Kitty".to_string(),
                    title: tab_title.clone(),
                    icon_hints: Vec::new(),
                    context: tab_ctx.clone(),
                    search_terms: vec!["kitty".to_string(), tab_ctx],
                    parent_id: parent_window.clone(),
                    badges: vec!["Tab".to_string()],
                    active: tab_active,
                    recency: if tab_active { 3500.0 } else { 0.0 },
                    activation: json!({
                        "socket": sock_path,
                        "socket_dev": sdev,
                        "socket_ino": sino,
                        "pid": pid,
                        "birth": birth,
                        "os_window_id": os_id,
                        "tab_id": tab_id,
                        "address": host_address,
                        "target": "tab",
                    }),
                });

                for win in windows {
                    let win_id = win.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                    if win_id <= 0 {
                        continue;
                    }
                    let cwd = canonical_path(win.get("cwd").and_then(|v| v.as_str()).unwrap_or(""));
                    let wtitle = win
                        .get("title")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| {
                            if !tab_title.is_empty() {
                                tab_title.clone()
                            } else {
                                "Kitty pane".to_string()
                            }
                        });
                    let active = tab_active
                        && win
                            .get("is_focused")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                    let pane_id = stable_id(
                        "kitty",
                        &[
                            sock_path.clone(),
                            sdev.to_string(),
                            sino.to_string(),
                            pid.to_string(),
                            birth.clone(),
                            os_id.to_string(),
                            "pane".to_string(),
                            win_id.to_string(),
                        ],
                    );
                    let act = json!({
                        "socket": sock_path,
                        "socket_dev": sdev,
                        "socket_ino": sino,
                        "pid": pid,
                        "birth": birth,
                        "os_window_id": os_id,
                        "window_id": win_id,
                        "address": host_address,
                        "target": "window",
                    });
                    items.push(Thing {
                        id: pane_id.clone(),
                        kind: "terminal-pane".to_string(),
                        provider: "Kitty".to_string(),
                        title: wtitle.clone(),
                        icon_hints: Vec::new(),
                        context: if !cwd.is_empty() {
                            cwd.clone()
                        } else {
                            tab_title.clone()
                        },
                        search_terms: vec!["kitty".to_string(), cwd.clone(), tab_title.clone()],
                        parent_id: tab_thing_id.clone(),
                        badges: vec!["Pane".to_string()],
                        active,
                        recency: if active { 3800.0 } else { 0.0 },
                        activation: act.clone(),
                    });
                    surfaces.push(SurfaceMeta {
                        provider: "kitty".to_string(),
                        item_id: pane_id,
                        pid,
                        title: wtitle,
                        cwd,
                        activation: act,
                    });
                }
            }
        }
    }

    (
        ProviderScan {
            items,
            warnings,
        },
        surfaces,
    )
}

// ---------------------------------------------------------------- Provider 3: Herdr (Direct Unix Socket!)

fn title_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut cap = true;
    for ch in s.chars() {
        if ch.is_alphanumeric() {
            if cap {
                for u in ch.to_uppercase() {
                    out.push(u);
                }
                cap = false;
            } else {
                for l in ch.to_lowercase() {
                    out.push(l);
                }
            }
        } else {
            out.push(ch);
            cap = true;
        }
    }
    out
}

fn herdr_server_pid_for_socket(socket_path: &str, procs: &ProcTable) -> i32 {
    let mut sock_inode = String::new();
    if let Ok(unix_txt) = fs::read_to_string("/proc/net/unix") {
        for line in unix_txt.lines().skip(1) {
            let fields: Vec<&str> = line.split_ascii_whitespace().collect();
            if fields.len() >= 8 && fields[7] == socket_path {
                sock_inode = fields[6].to_string();
                break;
            }
        }
    }
    if sock_inode.is_empty() {
        return 0;
    }
    let marker = format!("socket:[{}]", sock_inode);
    for p in procs.named(&["herdr"]) {
        if !p.argv.iter().any(|a| a == "server") {
            continue;
        }
        if let Ok(rd) = fs::read_dir(format!("/proc/{}/fd", p.pid)) {
            for e in rd.flatten() {
                if fs::read_link(e.path())
                    .map(|l| l.to_string_lossy() == marker)
                    .unwrap_or(false)
                {
                    return p.pid;
                }
            }
        }
    }
    0
}

fn herdr_session_processes<'a>(procs: &'a ProcTable, session_name: &str) -> Vec<&'a ProcInfo> {
    let mut matches = Vec::new();
    for p in procs.named(&["herdr"]) {
        if p.argv.iter().any(|a| a == "server") {
            continue;
        }
        let mut sess = "default";
        for i in 0..p.argv.len().saturating_sub(1) {
            if p.argv[i] == "--session" {
                sess = &p.argv[i + 1];
            } else if p.argv[i] == "attach" && i > 0 && p.argv[i - 1] == "session" {
                sess = &p.argv[i + 1];
            }
        }
        if sess == session_name {
            matches.push(p);
        }
    }
    matches
}

fn discover_herdr_sessions(procs: &ProcTable) -> Vec<(String, String)> {
    let uid = current_uid();
    let mut found: Vec<(String, String)> = Vec::new();
    let mut seen_socks: HashSet<String> = HashSet::new();

    // Fast path: check running herdr server processes + default ~/.config/herdr/herdr.sock directly (0 ms!)
    let home = std::env::var("HOME").unwrap_or_default();
    let default_sock = format!("{}/.config/herdr/herdr.sock", home);
    if let Ok(meta) = fs::symlink_metadata(&default_sock) {
        if meta.uid() == uid && meta.file_type().is_socket() {
            seen_socks.insert(default_sock.clone());
            found.push(("default".to_string(), default_sock));
        }
    }
    // Check any named sessions under ~/.config/herdr/sessions/<name>/herdr.sock or $XDG_RUNTIME_DIR/herdr*
    let sessions_dir = PathBuf::from(&home).join(".config/herdr/sessions");
    if let Ok(rd) = fs::read_dir(&sessions_dir) {
        for e in rd.flatten() {
            let s = e.path().join("herdr.sock");
            let s_str = s.to_string_lossy().into_owned();
            if !seen_socks.contains(&s_str) {
                if let Ok(meta) = fs::symlink_metadata(&s) {
                    if meta.uid() == uid && meta.file_type().is_socket() {
                        let name = e
                            .file_name()
                            .to_str()
                            .unwrap_or("default")
                            .to_string();
                        seen_socks.insert(s_str.clone());
                        found.push((name, s_str));
                    }
                }
            }
        }
    }
    // Check if any herdr server processes are running with custom --socket / --session
    for p in procs.named(&["herdr"]) {
        if !p.argv.iter().any(|a| a == "server") {
            continue;
        }
        let mut sess_name = "default".to_string();
        let mut sock_override = String::new();
        for i in 0..p.argv.len().saturating_sub(1) {
            if p.argv[i] == "--session" {
                sess_name = p.argv[i + 1].clone();
            } else if p.argv[i] == "--socket" {
                sock_override = p.argv[i + 1].clone();
            }
        }
        if !sock_override.is_empty() && !seen_socks.contains(&sock_override) {
            if let Ok(meta) = fs::symlink_metadata(&sock_override) {
                if meta.uid() == uid && meta.file_type().is_socket() {
                    seen_socks.insert(sock_override.clone());
                    found.push((sess_name, sock_override));
                }
            }
        }
    }
    found
}

fn scan_herdr(
    procs: &ProcTable,
    hypr_clients: &[HyprClientMeta],
) -> (ProviderScan, Vec<HerdrPaneMeta>, Vec<HerdrSessionMeta>) {
    let mut items = Vec::new();
    let mut warnings = Vec::new();
    let mut panes_meta = Vec::new();
    let mut sessions_meta = Vec::new();
    let uid = current_uid();
    let managed_pids: HashSet<i32> = hypr_clients.iter().map(|c| c.pid).collect();

    for (name, socket_path) in discover_herdr_sessions(procs) {
        let Ok(smeta) = fs::symlink_metadata(&socket_path) else {
            continue;
        };
        if smeta.uid() != uid || !smeta.file_type().is_socket() {
            continue;
        }
        let server_pid = herdr_server_pid_for_socket(&socket_path, procs);
        let birth = if server_pid > 0 {
            procs
                .get(server_pid)
                .map(|p| p.start_time.clone())
                .unwrap_or_else(|| process_birth(server_pid))
        } else {
            format!("socket-{}", smeta.ino())
        };
        let resp = match unix_json_line_request(
            &socket_path,
            &json!({"id": "everything:snapshot", "method": "session.snapshot", "params": {}}),
            1100,
        ) {
            Ok(v) => v,
            Err(_) => {
                // Stale socket file with no live server — skip quietly if server_pid == 0
                if server_pid > 0 {
                    warnings.push(format!("Herdr session {}: socket did not respond", name));
                }
                continue;
            }
        };
        let Some(snapshot) = resp
            .get("result")
            .filter(|r| r.get("type").and_then(|v| v.as_str()) == Some("session_snapshot"))
            .and_then(|r| r.get("snapshot"))
            .and_then(|s| s.as_object())
        else {
            warnings.push(format!("Herdr session {}: missing snapshot payload", name));
            continue;
        };

        let sdev = smeta.dev();
        let sino = smeta.ino();
        let id_prefix = [
            socket_path.clone(),
            server_pid.to_string(),
            birth.clone(),
            sdev.to_string(),
            sino.to_string(),
        ];

        // Find session host windows
        let mut hosts: Vec<Value> = Vec::new();
        for p in herdr_session_processes(procs, &name) {
            if let Some(anc) = procs.ancestor_pid_in(p.pid, &managed_pids) {
                let clients: Vec<&HyprClientMeta> =
                    hypr_clients.iter().filter(|c| c.pid == anc).collect();
                if clients.len() == 1 {
                    let h = json!({"address": clients[0].address, "pid": anc.to_string()});
                    if !hosts.contains(&h) {
                        hosts.push(h);
                    }
                }
            }
        }

        let mk_act = |kind: &str, target_id: &str| -> Value {
            json!({
                "socket": socket_path,
                "session": name,
                "server_pid": server_pid,
                "birth": birth,
                "socket_dev": sdev,
                "socket_ino": sino,
                "target_kind": kind,
                "target_id": target_id,
                "hosts": hosts,
            })
        };

        let focused_ws = snapshot
            .get("focused_workspace_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let focused_tab = snapshot
            .get("focused_tab_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let focused_pane = snapshot
            .get("focused_pane_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let mut sess_parts = id_prefix.to_vec();
        sess_parts.push("session".to_string());
        sess_parts.push(name.clone());
        let session_id = stable_id("herdr", &sess_parts);
        let ver = snapshot.get("version").and_then(|v| v.as_str()).unwrap_or("");
        let sess_ctx = format!("Herdr {} · local session", ver)
            .replace("  ", " ")
            .trim_matches(|c| c == ' ' || c == '·')
            .to_string();

        items.push(Thing {
            id: session_id.clone(),
            kind: "herdr-session".to_string(),
            provider: "Herdr".to_string(),
            title: name.clone(),
            icon_hints: Vec::new(),
            context: sess_ctx,
            search_terms: vec!["herdr".to_string(), socket_path.clone()],
            parent_id: String::new(),
            badges: vec![
                "Session".to_string(),
                if !hosts.is_empty() {
                    "Attached".to_string()
                } else {
                    "Detached".to_string()
                },
            ],
            active: !hosts.is_empty() && !focused_ws.is_empty(),
            recency: if !hosts.is_empty() { 3000.0 } else { 0.0 },
            activation: mk_act("session", ""),
        });

        let extract_unique = |key: &str, id_key: &str| -> Vec<&Map<String, Value>> {
            let Some(arr) = snapshot.get(key).and_then(|v| v.as_array()) else {
                return Vec::new();
            };
            let valid: Vec<&Map<String, Value>> = arr
                .iter()
                .filter_map(|v| v.as_object())
                .filter(|o| {
                    o.get(id_key)
                        .and_then(|v| v.as_str())
                        .map(is_valid_herdr_native_id)
                        .unwrap_or(false)
                })
                .collect();
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for o in &valid {
                if let Some(id) = o.get(id_key).and_then(|v| v.as_str()) {
                    *counts.entry(id).or_insert(0) += 1;
                }
            }
            valid
                .into_iter()
                .filter(|o| {
                    o.get(id_key)
                        .and_then(|v| v.as_str())
                        .and_then(|id| counts.get(id))
                        .copied()
                        == Some(1)
                })
                .collect()
        };

        let mut ws_ids: HashMap<String, String> = HashMap::new();
        let mut tab_ids: HashMap<String, String> = HashMap::new();
        let mut pane_ids: HashMap<String, String> = HashMap::new();

        for ws in extract_unique("workspaces", "workspace_id") {
            let nid = ws["workspace_id"].as_str().unwrap_or("");
            let mut parts = id_prefix.to_vec();
            parts.push("workspace".to_string());
            parts.push(nid.to_string());
            let item_id = stable_id("herdr", &parts);
            ws_ids.insert(nid.to_string(), item_id.clone());
            let status = ws
                .get("agent_status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let title = ws
                .get("label")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or(nid);
            let tc = ws.get("tab_count").and_then(|v| v.as_i64()).unwrap_or(0);
            let pc = ws.get("pane_count").and_then(|v| v.as_i64()).unwrap_or(0);
            items.push(Thing {
                id: item_id,
                kind: "herdr-workspace".to_string(),
                provider: "Herdr".to_string(),
                title: title.to_string(),
                icon_hints: Vec::new(),
                context: format!("{} tabs · {} panes", tc, pc),
                search_terms: vec![
                    "herdr".to_string(),
                    name.clone(),
                    nid.to_string(),
                    status.to_string(),
                ],
                parent_id: session_id.clone(),
                badges: vec!["Workspace".to_string(), title_case(status)],
                active: nid == focused_ws,
                recency: if nid == focused_ws { 3400.0 } else { 0.0 },
                activation: mk_act("workspace", nid),
            });
        }

        for tab in extract_unique("tabs", "tab_id") {
            let nid = tab["tab_id"].as_str().unwrap_or("");
            let wsid = tab
                .get("workspace_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let mut parts = id_prefix.to_vec();
            parts.push("tab".to_string());
            parts.push(nid.to_string());
            let item_id = stable_id("herdr", &parts);
            tab_ids.insert(nid.to_string(), item_id.clone());
            let status = tab
                .get("agent_status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let title = tab
                .get("label")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    if let Some(num) = tab.get("number").and_then(|v| v.as_i64()) {
                        format!("Tab {}", num)
                    } else {
                        format!("Tab {}", nid)
                    }
                });
            let pc = tab.get("pane_count").and_then(|v| v.as_i64()).unwrap_or(0);
            items.push(Thing {
                id: item_id,
                kind: "herdr-tab".to_string(),
                provider: "Herdr".to_string(),
                title,
                icon_hints: Vec::new(),
                context: format!("{} panes · {}", pc, name),
                search_terms: vec![
                    "herdr".to_string(),
                    wsid.to_string(),
                    nid.to_string(),
                    status.to_string(),
                ],
                parent_id: ws_ids
                    .get(wsid)
                    .cloned()
                    .unwrap_or_else(|| session_id.clone()),
                badges: vec!["Tab".to_string(), title_case(status)],
                active: nid == focused_tab,
                recency: if nid == focused_tab { 3600.0 } else { 0.0 },
                activation: mk_act("tab", nid),
            });
        }

        for pane in extract_unique("panes", "pane_id") {
            let nid = pane["pane_id"].as_str().unwrap_or("");
            let tid = pane.get("tab_id").and_then(|v| v.as_str()).unwrap_or("");
            let mut parts = id_prefix.to_vec();
            parts.push("pane".to_string());
            parts.push(nid.to_string());
            let item_id = stable_id("herdr", &parts);
            pane_ids.insert(nid.to_string(), item_id.clone());
            let raw_cwd = pane
                .get("foreground_cwd")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .or_else(|| pane.get("cwd").and_then(|v| v.as_str()))
                .unwrap_or("");
            let cwd = canonical_path(raw_cwd);
            let title = pane
                .get("terminal_title_stripped")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    pane.get("terminal_title")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                })
                .map(|s| s.to_string())
                .or_else(|| {
                    Path::new(&cwd)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| nid.to_string());
            let status = pane
                .get("agent_status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let act = mk_act("pane", nid);
            items.push(Thing {
                id: item_id.clone(),
                kind: "herdr-pane".to_string(),
                provider: "Herdr".to_string(),
                title,
                icon_hints: Vec::new(),
                context: if !cwd.is_empty() {
                    cwd.clone()
                } else {
                    name.clone()
                },
                search_terms: vec![
                    "herdr".to_string(),
                    nid.to_string(),
                    tid.to_string(),
                    status.to_string(),
                ],
                parent_id: tab_ids
                    .get(tid)
                    .cloned()
                    .unwrap_or_else(|| session_id.clone()),
                badges: vec!["Pane".to_string(), title_case(status)],
                active: nid == focused_pane,
                recency: if nid == focused_pane { 3800.0 } else { 0.0 },
                activation: act.clone(),
            });
            panes_meta.push(HerdrPaneMeta {
                item_id,
                socket: socket_path.clone(),
                server_pid,
                pane_id: nid.to_string(),
                cwd,
                activation: act,
            });
        }

        for agent in extract_unique("agents", "pane_id") {
            let pid_str = agent["pane_id"].as_str().unwrap_or("");
            let id_val = agent
                .get("agent_session")
                .and_then(|v| v.get("value"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or(pid_str);
            let agent_name = agent
                .get("agent")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("Agent");
            let status = agent
                .get("agent_status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let mut parts = id_prefix.to_vec();
            parts.push("agent".to_string());
            parts.push(agent_name.to_string());
            parts.push(id_val.to_string());
            parts.push(pid_str.to_string());
            let item_id = stable_id("herdr", &parts);
            let raw_cwd = agent
                .get("foreground_cwd")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .or_else(|| agent.get("cwd").and_then(|v| v.as_str()))
                .unwrap_or("");
            let cwd = canonical_path(raw_cwd);
            let term_title = agent
                .get("terminal_title_stripped")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    agent
                        .get("terminal_title")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                });
            let recency = if pid_str == focused_pane {
                4000.0
            } else {
                agent
                    .get("state_change_seq")
                    .and_then(|v| v.as_i64())
                    .map(|n| (n.rem_euclid(1000)) as f64)
                    .unwrap_or(0.0)
            };
            items.push(Thing {
                id: item_id,
                kind: "herdr-agent".to_string(),
                provider: "Herdr".to_string(),
                title: term_title
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| title_case(agent_name)),
                icon_hints: Vec::new(),
                context: if !cwd.is_empty() { cwd } else { name.clone() },
                search_terms: vec![
                    "herdr".to_string(),
                    agent_name.to_string(),
                    id_val.to_string(),
                    pid_str.to_string(),
                    status.to_string(),
                ],
                parent_id: pane_ids
                    .get(pid_str)
                    .cloned()
                    .unwrap_or_else(|| session_id.clone()),
                badges: vec![title_case(agent_name), title_case(status)],
                active: pid_str == focused_pane
                    && agent
                        .get("focused")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                recency,
                activation: mk_act("pane", pid_str),
            });
        }

        sessions_meta.push(HerdrSessionMeta { server_pid });
    }

    (
        ProviderScan {
            items,
            warnings,
        },
        panes_meta,
        sessions_meta,
    )
}

// ---------------------------------------------------------------- Provider 4: tmux

fn tmux_records(socket: &str, cmd: &[&str], fields: &[&str]) -> Result<Vec<Vec<String>>, String> {
    let fmt = fields
        .iter()
        .map(|f| format!("#{{{}}}", f))
        .collect::<Vec<_>>()
        .join(&TMUX_SEP.to_string());
    let mut args = vec!["-S", socket];
    args.extend_from_slice(cmd);
    args.push("-F");
    args.push(&fmt);
    let out = Command::new("tmux")
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("tmux failed: {}", e))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if err.is_empty() {
            "tmux query failed".to_string()
        } else {
            err
        });
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut rows = Vec::new();
    for line in text.lines() {
        let parts: Vec<String> = line.split(TMUX_SEP).map(|s| s.to_string()).collect();
        if parts.len() == fields.len() {
            rows.push(parts);
        }
    }
    Ok(rows)
}

fn scan_tmux(procs: &ProcTable) -> (ProviderScan, Vec<TmuxPaneMeta>) {
    let uid = current_uid();
    let mut cands: HashSet<String> = HashSet::new();
    if let Ok(rd) = fs::read_dir(format!("/tmp/tmux-{}", uid)) {
        for e in rd.flatten() {
            cands.insert(e.path().to_string_lossy().into_owned());
        }
    }
    if let Ok(rd) = fs::read_dir(runtime_dir()) {
        for e in rd.flatten() {
            if e.file_name()
                .to_str()
                .map(|s| s.to_ascii_lowercase().contains("tmux"))
                .unwrap_or(false)
            {
                cands.insert(e.path().to_string_lossy().into_owned());
            }
        }
    }
    for p in procs.named(&["tmux"]) {
        for i in 0..p.argv.len().saturating_sub(1) {
            if p.argv[i] == "-S" {
                cands.insert(canonical_path(&p.argv[i + 1]));
            }
        }
    }

    let mut valid: Vec<String> = Vec::new();
    for c in cands {
        if let Ok(meta) = fs::symlink_metadata(&c) {
            if meta.uid() == uid && meta.file_type().is_socket() {
                valid.push(canonical_path(&c));
            }
        }
    }
    valid.sort();
    valid.dedup();

    let mut items = Vec::new();
    let mut warnings = Vec::new();
    let mut panes_meta = Vec::new();
    let now = now_epoch();

    let recent = |val: &str, bonus: f64| -> f64 {
        let age = val
            .parse::<f64>()
            .map(|v| (now - v).max(0.0))
            .unwrap_or(1000.0);
        bonus + (1000.0 - age.min(1000.0)).max(0.0)
    };

    for sock in valid {
        let sessions = match tmux_records(
            &sock,
            &["list-sessions"],
            &[
                "pid",
                "session_id",
                "session_name",
                "session_attached",
                "session_activity",
            ],
        ) {
            Ok(r) => r,
            Err(e) => {
                warnings.push(format!(
                    "tmux socket {}: {}",
                    Path::new(&sock)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("tmux"),
                    e
                ));
                continue;
            }
        };
        let windows = tmux_records(
            &sock,
            &["list-windows", "-a"],
            &[
                "session_id",
                "window_id",
                "window_name",
                "window_active",
                "window_activity",
            ],
        )
        .unwrap_or_default();
        let panes = tmux_records(
            &sock,
            &["list-panes", "-a"],
            &[
                "session_id",
                "window_id",
                "pane_id",
                "pane_title",
                "pane_current_path",
                "pane_active",
                "pane_pid",
            ],
        )
        .unwrap_or_default();
        let clients = tmux_records(
            &sock,
            &["list-clients"],
            &["client_name", "client_pid", "client_session", "client_tty"],
        )
        .unwrap_or_default();

        let server_pid = sessions
            .first()
            .and_then(|s| s[0].parse::<i32>().ok())
            .unwrap_or(0);
        let birth = procs
            .get(server_pid)
            .map(|p| p.start_time.clone())
            .unwrap_or_else(|| process_birth(server_pid));
        let mut session_ids: HashMap<String, String> = HashMap::new();
        let mut window_ids: HashMap<String, String> = HashMap::new();

        for row in &sessions {
            let nid = &row[1];
            if !is_valid_tmux_native_id(nid) {
                continue;
            }
            let item_id = stable_id(
                "tmux",
                &[sock.clone(), server_pid.to_string(), birth.clone(), nid.clone()],
            );
            session_ids.insert(nid.clone(), item_id.clone());
            let attached = &row[3];
            items.push(Thing {
                id: item_id,
                kind: "tmux-session".to_string(),
                provider: "tmux".to_string(),
                title: if row[2].is_empty() {
                    nid.clone()
                } else {
                    row[2].clone()
                },
                icon_hints: Vec::new(),
                context: format!(
                    "{} attached client{}",
                    attached,
                    if attached == "1" { "" } else { "s" }
                ),
                search_terms: vec!["tmux".to_string(), sock.clone(), nid.clone()],
                parent_id: String::new(),
                badges: vec![
                    "Session".to_string(),
                    if attached != "0" {
                        "Attached".to_string()
                    } else {
                        "Detached".to_string()
                    },
                ],
                active: false,
                recency: recent(&row[4], 0.0),
                activation: json!({
                    "socket": sock,
                    "server_pid": server_pid,
                    "birth": birth,
                    "target_id": nid,
                    "target_kind": "session",
                    "session_id": nid,
                    "clients": clients,
                }),
            });
        }

        for row in &windows {
            let sid = &row[0];
            let nid = &row[1];
            if !is_valid_tmux_native_id(nid) {
                continue;
            }
            let item_id = stable_id(
                "tmux",
                &[sock.clone(), server_pid.to_string(), birth.clone(), nid.clone()],
            );
            window_ids.insert(nid.clone(), item_id.clone());
            let active = row[3] == "1";
            items.push(Thing {
                id: item_id,
                kind: "tmux-window".to_string(),
                provider: "tmux".to_string(),
                title: if row[2].is_empty() {
                    nid.clone()
                } else {
                    row[2].clone()
                },
                icon_hints: Vec::new(),
                context: format!("tmux window {}", nid),
                search_terms: vec!["tmux".to_string(), sid.clone(), nid.clone()],
                parent_id: session_ids.get(sid).cloned().unwrap_or_default(),
                badges: vec!["Window".to_string()],
                active,
                recency: recent(&row[4], if active { 3000.0 } else { 0.0 }),
                activation: json!({
                    "socket": sock,
                    "server_pid": server_pid,
                    "birth": birth,
                    "target_id": nid,
                    "target_kind": "window",
                    "session_id": sid,
                    "clients": clients,
                }),
            });
        }

        for row in &panes {
            let sid = &row[0];
            let wid = &row[1];
            let nid = &row[2];
            if !is_valid_tmux_native_id(nid) {
                continue;
            }
            let path = canonical_path(&row[4]);
            let active = row[5] == "1";
            let pane_pid = row[6].parse::<i32>().unwrap_or(0);
            let item_id = stable_id(
                "tmux",
                &[sock.clone(), server_pid.to_string(), birth.clone(), nid.clone()],
            );
            let act = json!({
                "socket": sock,
                "server_pid": server_pid,
                "birth": birth,
                "target_id": nid,
                "target_kind": "pane",
                "session_id": sid,
                "clients": clients,
                "pane_pid": pane_pid,
            });
            let title = if !row[3].is_empty() {
                row[3].clone()
            } else {
                Path::new(&path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .filter(|s| !s.is_empty())
                    .unwrap_or(nid)
                    .to_string()
            };
            items.push(Thing {
                id: item_id.clone(),
                kind: "tmux-pane".to_string(),
                provider: "tmux".to_string(),
                title,
                icon_hints: Vec::new(),
                context: if !path.is_empty() {
                    path.clone()
                } else {
                    format!("tmux pane {}", nid)
                },
                search_terms: vec![
                    "tmux".to_string(),
                    sid.clone(),
                    wid.clone(),
                    nid.clone(),
                    path,
                ],
                parent_id: window_ids.get(wid).cloned().unwrap_or_default(),
                badges: vec!["Pane".to_string()],
                active,
                recency: if active { 3200.0 } else { 0.0 },
                activation: act.clone(),
            });
            panes_meta.push(TmuxPaneMeta {
                item_id,
                pane_pid,
                activation: act,
            });
        }
    }

    (
        ProviderScan {
            items,
            warnings,
        },
        panes_meta,
    )
}

// ---------------------------------------------------------------- Provider 5: Neovim

fn discover_nvim_sockets(procs: &ProcTable) -> Vec<String> {
    let uid = current_uid();
    let mut cands: HashSet<String> = HashSet::new();
    let tmpdir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let roots = [runtime_dir(), format!("{}/nvim.{}", tmpdir, current_username())];

    for root in roots {
        let Ok(rmeta) = fs::symlink_metadata(&root) else {
            continue;
        };
        if rmeta.uid() != uid || !rmeta.is_dir() {
            continue;
        }
        let mut pending = vec![(PathBuf::from(root), 0usize)];
        let mut inspected = 0usize;
        while let Some((dir, depth)) = pending.pop() {
            if inspected >= 4096 {
                break;
            }
            let Ok(rd) = fs::read_dir(&dir) else {
                continue;
            };
            for e in rd.flatten() {
                inspected += 1;
                if inspected > 4096 {
                    break;
                }
                let Ok(m) = fs::symlink_metadata(e.path()) else {
                    continue;
                };
                if m.uid() != uid {
                    continue;
                }
                let fname = e.file_name();
                let name = fname.to_str().unwrap_or("");
                if m.file_type().is_socket() && name.starts_with("nvim") {
                    cands.insert(e.path().to_string_lossy().into_owned());
                } else if depth == 0 && m.is_dir() {
                    pending.push((e.path(), 1));
                }
            }
        }
    }
    for p in procs.named(&["nvim", "neovim"]) {
        for i in 0..p.argv.len().saturating_sub(1) {
            if p.argv[i] == "--listen" {
                cands.insert(canonical_path(&p.argv[i + 1]));
            }
        }
    }
    let mut out = Vec::new();
    for c in cands {
        if let Ok(m) = fs::symlink_metadata(&c) {
            if m.uid() == uid && m.file_type().is_socket() {
                out.push(canonical_path(&c));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn nvim_query(socket: &str) -> Result<Value, String> {
    let out = Command::new("nvim")
        .args(["--server", socket, "--remote-expr", NVIM_QUERY_EXPR])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("nvim failed: {}", e))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if err.is_empty() {
            "Neovim socket did not answer".to_string()
        } else {
            err
        });
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut val: Value = serde_json::from_str(text.trim())
        .map_err(|_| "Neovim returned invalid buffer JSON".to_string())?;
    if let Some(s) = val.as_str() {
        val = serde_json::from_str(s)
            .map_err(|_| "Neovim returned invalid buffer JSON".to_string())?;
    }
    if !val.is_object() || !val.get("buffers").map(|b| b.is_array()).unwrap_or(false) {
        return Err("Neovim buffer response has the wrong shape".to_string());
    }
    Ok(val)
}

fn scan_neovim(procs: &ProcTable, meta: &ProviderMeta) -> ProviderScan {
    let mut items = Vec::new();
    let mut warnings = Vec::new();

    for sock in discover_nvim_sockets(procs) {
        let resp = match nvim_query(&sock) {
            Ok(v) => v,
            Err(e) => {
                warnings.push(format!(
                    "Neovim socket {}: {}",
                    Path::new(&sock)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("nvim"),
                    e
                ));
                continue;
            }
        };
        let pid = resp.get("pid").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
        let Some(pinfo) = procs.get(pid) else {
            continue;
        };
        let exe = pinfo
            .argv
            .first()
            .and_then(|a| Path::new(a).file_name().and_then(|s| s.to_str()))
            .unwrap_or("")
            .to_ascii_lowercase();
        let cl = pinfo.comm.to_ascii_lowercase();
        if !matches!(cl.as_str(), "nvim" | "neovim") && !matches!(exe.as_str(), "nvim" | "neovim") {
            continue;
        }
        let birth = pinfo.start_time.clone();
        let current_buf = resp.get("current").and_then(|v| v.as_i64()).unwrap_or(0);
        let fallback_cwd = proc_cwd(pid);
        let editor_cwd = canonical_path(
            resp.get("cwd")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or(&fallback_cwd),
        );
        let term_title = resp
            .get("terminal_title")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Resolve container route
        let (route, parent_id) = resolve_nvim_route(procs, meta, pid, &editor_cwd, term_title);
        let buffers = resp["buffers"].as_array().cloned().unwrap_or_default();
        let newest = buffers
            .iter()
            .filter_map(|b| b.get("lastused").and_then(|v| v.as_f64()))
            .fold(0.0f64, f64::max);

        for buf in buffers {
            if buf.get("listed").and_then(|v| v.as_bool()) == Some(false) {
                continue;
            }
            let bufnr = buf.get("bufnr").and_then(|v| v.as_i64()).unwrap_or(0);
            if bufnr <= 0 {
                continue;
            }
            let name = canonical_path(buf.get("name").and_then(|v| v.as_str()).unwrap_or(""));
            let title = if !name.is_empty() {
                Path::new(&name)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&name)
                    .to_string()
            } else {
                format!("[No Name {}]", bufnr)
            };
            let dir = if !name.is_empty() {
                Path::new(&name)
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|| editor_cwd.clone())
            } else {
                editor_cwd.clone()
            };
            let changed = buf
                .get("changed")
                .and_then(|v| v.as_i64().map(|n| n != 0).or_else(|| v.as_bool()))
                .unwrap_or(false);
            let loaded = buf
                .get("loaded")
                .and_then(|v| v.as_i64().map(|n| n != 0).or_else(|| v.as_bool()))
                .unwrap_or(false);
            let has_windows = buf
                .get("windows")
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false);
            let item_id = stable_id(
                "neovim",
                &[
                    sock.clone(),
                    pid.to_string(),
                    birth.clone(),
                    bufnr.to_string(),
                    if name.is_empty() {
                        "unnamed".to_string()
                    } else {
                        name.clone()
                    },
                ],
            );
            let mut badges = vec!["Buffer".to_string()];
            if changed {
                badges.push("Modified".to_string());
            }
            if !loaded {
                badges.push("Unloaded".to_string());
            }
            if has_windows {
                badges.push("Visible".to_string());
            }
            let last_used = buf.get("lastused").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let recent = (1000.0 - (newest - last_used).min(1000.0)).max(0.0);

            items.push(Thing {
                id: item_id,
                kind: "neovim-buffer".to_string(),
                provider: "Neovim".to_string(),
                title: if changed {
                    format!("{} [+]", title)
                } else {
                    title
                },
                icon_hints: Vec::new(),
                context: if !dir.is_empty() {
                    dir
                } else {
                    format!(
                        "Neovim server {}",
                        Path::new(&sock)
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("nvim")
                    )
                },
                search_terms: vec![
                    "neovim".to_string(),
                    "nvim".to_string(),
                    name.clone(),
                    bufnr.to_string(),
                ],
                parent_id: parent_id.clone(),
                badges,
                active: bufnr == current_buf,
                recency: (if bufnr == current_buf { 3900.0 } else { 0.0 }) + recent,
                activation: json!({
                    "socket": sock,
                    "pid": pid,
                    "birth": birth,
                    "bufnr": bufnr,
                    "name": name,
                    "route": route,
                    "ambiguous_ghostty": false,
                }),
            });
        }
    }

    ProviderScan {
        items,
        warnings,
    }
}

fn resolve_nvim_route(
    procs: &ProcTable,
    meta: &ProviderMeta,
    pid: i32,
    cwd: &str,
    term_title: &str,
) -> (Value, String) {
    let tmux_matches: Vec<&TmuxPaneMeta> = meta
        .tmux_panes
        .iter()
        .filter(|p| p.pane_pid > 0 && procs.is_descendant(pid, p.pane_pid))
        .collect();
    if tmux_matches.len() == 1 {
        return (
            json!({"provider": "tmux", "activation": tmux_matches[0].activation}),
            tmux_matches[0].item_id.clone(),
        );
    }
    if tmux_matches.len() > 1 {
        return (json!({"provider": "remote-ui"}), String::new());
    }

    let herdr_spids: HashSet<i32> = meta
        .herdr_sessions
        .iter()
        .filter(|s| s.server_pid > 0 && procs.is_descendant(pid, s.server_pid))
        .map(|s| s.server_pid)
        .collect();
    if !herdr_spids.is_empty() {
        let env_vars = procs.environment(pid, &["HERDR_SOCKET_PATH", "HERDR_PANE_ID"]);
        let env_sock = env_vars.get("HERDR_SOCKET_PATH").map(|s| s.as_str()).unwrap_or("");
        let env_pane = env_vars.get("HERDR_PANE_ID").map(|s| s.as_str()).unwrap_or("");
        let env_matches: Vec<&HerdrPaneMeta> = meta
            .herdr_panes
            .iter()
            .filter(|p| {
                p.socket == env_sock
                    && p.pane_id == env_pane
                    && herdr_spids.contains(&p.server_pid)
            })
            .collect();
        if env_matches.len() == 1 {
            return (
                json!({"provider": "herdr", "activation": env_matches[0].activation}),
                env_matches[0].item_id.clone(),
            );
        }
        let cwd_matches: Vec<&HerdrPaneMeta> = meta
            .herdr_panes
            .iter()
            .filter(|p| herdr_spids.contains(&p.server_pid) && !cwd.is_empty() && canonical_path(&p.cwd) == cwd)
            .collect();
        if cwd_matches.len() == 1 {
            return (
                json!({"provider": "herdr", "activation": cwd_matches[0].activation}),
                cwd_matches[0].item_id.clone(),
            );
        }
        return (json!({"provider": "remote-ui"}), String::new());
    }

    let k_surfaces: Vec<&SurfaceMeta> = meta
        .kitty_surfaces
        .iter()
        .filter(|s| s.pid > 0 && procs.is_descendant(pid, s.pid))
        .collect();
    if !k_surfaces.is_empty() {
        let matched = if k_surfaces.len() == 1 {
            k_surfaces
        } else {
            k_surfaces
                .into_iter()
                .filter(|s| {
                    !cwd.is_empty()
                        && canonical_path(&s.cwd) == cwd
                        && !term_title.is_empty()
                        && s.title == term_title
                })
                .collect()
        };
        if matched.len() == 1 {
            return (
                json!({"provider": "kitty", "activation": matched[0].activation}),
                matched[0].item_id.clone(),
            );
        }
        return (json!({"provider": "remote-ui"}), String::new());
    }

    let managed: HashSet<i32> = meta.hypr_clients.iter().map(|c| c.pid).collect();
    if let Some(anc) = procs.ancestor_pid_in(pid, &managed) {
        let clients = meta.clients_for_pid(anc);
        if clients.len() == 1 {
            let c = clients[0];
            return (
                json!({
                    "provider": "hyprland",
                    "activation": {
                        "address": c.address,
                        "pid": c.pid,
                        "birth": process_birth(c.pid),
                    }
                }),
                c.item_id.clone(),
            );
        }
    }

    (json!({"provider": "remote-ui"}), String::new())
}

// ---------------------------------------------------------------- Activation

fn activate_provider(
    provider: &str,
    act: &Value,
    procs: &ProcTable,
    meta: &ProviderMeta,
) -> Result<(), String> {
    match provider {
        "hyprland" => {
            let addr = normalized_address(act.get("address").and_then(|v| v.as_str()).unwrap_or(""));
            let client = meta
                .client_by_address(&addr)
                .ok_or("window is no longer managed")?;
            let expected_pid = act.get("pid").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let expected_birth = act.get("birth").and_then(|v| v.as_str()).unwrap_or("");
            if client.pid != expected_pid || process_birth(client.pid) != expected_birth {
                return Err("window address was reused by another process".to_string());
            }
            hypr_focus_address(&addr)
        }
        "kitty" => {
            let sock = act.get("socket").and_then(|v| v.as_str()).unwrap_or("");
            let pid = act.get("pid").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let birth = act.get("birth").and_then(|v| v.as_str()).unwrap_or("");
            if process_birth(pid) != birth {
                return Err("Kitty process was replaced".to_string());
            }
            let smeta = fs::symlink_metadata(sock).map_err(|_| "Kitty socket closed")?;
            if smeta.uid() != current_uid() || !smeta.file_type().is_socket() {
                return Err("Kitty socket is not a current user socket".to_string());
            }
            if smeta.dev() != act.get("socket_dev").and_then(|v| v.as_u64()).unwrap_or(0)
                || smeta.ino() != act.get("socket_ino").and_then(|v| v.as_u64()).unwrap_or(0)
            {
                return Err("Kitty socket was replaced".to_string());
            }
            let target = act.get("target").and_then(|v| v.as_str()).unwrap_or("");
            let (cmd, id) = match target {
                "tab" => ("focus-tab", act.get("tab_id").and_then(|v| v.as_i64()).unwrap_or(0)),
                "window" => (
                    "focus-window",
                    act.get("window_id").and_then(|v| v.as_i64()).unwrap_or(0),
                ),
                _ => return Err("unknown Kitty activation target".to_string()),
            };
            if id <= 0 {
                return Err("invalid Kitty target id".to_string());
            }
            let resp = kitty_socket_cmd(
                sock,
                &json!({
                    "cmd": cmd,
                    "payload": {"match": format!("id:{}", id)},
                    "version": [0, 26, 0],
                    "no_response": false,
                }),
            )?;
            if resp.get("ok").and_then(|v| v.as_bool()) != Some(true) {
                return Err("Kitty target is stale".to_string());
            }
            let mut addr = normalized_address(act.get("address").and_then(|v| v.as_str()).unwrap_or(""));
            if addr.is_empty()
                || meta
                    .client_by_address(&addr)
                    .map(|c| c.pid != pid)
                    .unwrap_or(true)
            {
                if let Ok(raw) = hypr_ipc("j/activewindow") {
                    if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                        if v.get("pid").and_then(|p| p.as_i64()).unwrap_or(0) as i32 == pid {
                            addr = normalized_address(
                                v.get("address").and_then(|a| a.as_str()).unwrap_or(""),
                            );
                        }
                    }
                }
            }
            if addr.is_empty() {
                if let Some(c) = meta.clients_for_pid(pid).first() {
                    addr = c.address.clone();
                }
            }
            if addr.is_empty() {
                return Err("Kitty focused its pane but its managed window could not be identified".to_string());
            }
            hypr_focus_address(&addr)
        }
        "herdr" => {
            let sock = act.get("socket").and_then(|v| v.as_str()).unwrap_or("");
            let smeta = fs::symlink_metadata(sock).map_err(|_| "Herdr session socket closed")?;
            if smeta.uid() != current_uid() || !smeta.file_type().is_socket() {
                return Err("Herdr session socket closed".to_string());
            }
            if smeta.dev() != act.get("socket_dev").and_then(|v| v.as_u64()).unwrap_or(0)
                || smeta.ino() != act.get("socket_ino").and_then(|v| v.as_u64()).unwrap_or(0)
            {
                return Err("Herdr session socket was replaced".to_string());
            }
            let server_pid = act.get("server_pid").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            if server_pid > 0
                && process_birth(server_pid) != act.get("birth").and_then(|v| v.as_str()).unwrap_or("")
            {
                return Err("Herdr server was replaced".to_string());
            }
            let kind = act.get("target_kind").and_then(|v| v.as_str()).unwrap_or("");
            let tid = act.get("target_id").and_then(|v| v.as_str()).unwrap_or("");
            let method = match kind {
                "workspace" => Some(("workspace.focus", "workspace_id")),
                "tab" => Some(("tab.focus", "tab_id")),
                "pane" => Some(("pane.focus", "pane_id")),
                "session" => None,
                _ => return Err("Unknown Herdr activation target".to_string()),
            };
            if let Some((m, k)) = method {
                if !is_valid_herdr_native_id(tid) {
                    return Err("Herdr target has no exact native ID".to_string());
                }
                let resp = unix_json_line_request(
                    sock,
                    &json!({"id": "everything:focus", "method": m, "params": {k: tid}}),
                    1000,
                )?;
                if let Some(err) = resp.get("error").and_then(|v| v.as_object()) {
                    return Err(err
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Herdr target closed")
                        .to_string());
                }
            }
            let session = act.get("session").and_then(|v| v.as_str()).unwrap_or("default");
            let routes: Vec<(String, Value)> = herdr_session_processes(procs, session)
                .into_iter()
                .filter_map(|p| {
                    let cwd = proc_cwd(p.pid);
                    meta.route_for_process(procs, p.pid, "", &cwd)
                })
                .collect();
            if routes.len() == 1 {
                return activate_provider(&routes[0].0, &routes[0].1, procs, meta);
            }
            if act.get("allow_new_client").and_then(|v| v.as_bool()) == Some(false) {
                return Ok(());
            }
            spawn_detached(&[
                "omarchy-launch-terminal".to_string(),
                "herdr".to_string(),
                "session".to_string(),
                "attach".to_string(),
                session.to_string(),
            ])
        }
        "tmux" => {
            let sock = act.get("socket").and_then(|v| v.as_str()).unwrap_or("");
            let server_pid = act.get("server_pid").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            if process_birth(server_pid) != act.get("birth").and_then(|v| v.as_str()).unwrap_or("") {
                return Err("tmux server was replaced".to_string());
            }
            let smeta = fs::symlink_metadata(sock).map_err(|_| "tmux socket closed")?;
            if smeta.uid() != current_uid() || !smeta.file_type().is_socket() {
                return Err("tmux socket is not owned by the current user".to_string());
            }
            let target = act.get("target_id").and_then(|v| v.as_str()).unwrap_or("");
            if !is_valid_tmux_native_id(target) {
                return Err("invalid tmux native target".to_string());
            }
            let live_clients = tmux_records(
                sock,
                &["list-clients"],
                &["client_name", "client_pid", "client_session", "client_tty"],
            )
            .unwrap_or_default();
            let mut routes = Vec::new();
            for row in &live_clients {
                if let Ok(cpid) = row[1].parse::<i32>() {
                    if procs.get(cpid).is_some() {
                        let cwd = proc_cwd(cpid);
                        if let Some(r) = meta.route_for_process(procs, cpid, "", &cwd) {
                            routes.push((row[0].clone(), r));
                        }
                    }
                }
            }
            if routes.len() == 1 {
                let (cname, (rprov, ract)) = &routes[0];
                let st = Command::new("tmux")
                    .args(["-S", sock, "switch-client", "-c", cname, "-t", target])
                    .stdin(Stdio::null())
                    .output()
                    .map_err(|_| "tmux switch-client failed".to_string())?;
                if !st.status.success() {
                    return Err("tmux target closed".to_string());
                }
                return activate_provider(rprov, ract, procs, meta);
            }
            if act.get("allow_new_client").and_then(|v| v.as_bool()) == Some(false) {
                if let Some(first) = live_clients.first() {
                    let _ = Command::new("tmux")
                        .args(["-S", sock, "switch-client", "-c", &first[0], "-t", target])
                        .stdin(Stdio::null())
                        .output();
                }
                return Ok(());
            }
            let sid = act.get("session_id").and_then(|v| v.as_str()).unwrap_or("");
            if !sid.starts_with('$') || !is_valid_tmux_native_id(sid) {
                return Err("tmux target has no live session".to_string());
            }
            let mut argv = vec![
                "omarchy-launch-terminal".to_string(),
                "tmux".to_string(),
                "-S".to_string(),
                sock.to_string(),
                "attach-session".to_string(),
                "-t".to_string(),
                sid.to_string(),
            ];
            if target.starts_with('@') {
                argv.extend([";".into(), "select-window".into(), "-t".into(), target.into()]);
            } else if target.starts_with('%') {
                argv.extend([";".into(), "select-pane".into(), "-t".into(), target.into()]);
            }
            spawn_detached(&argv)
        }
        "neovim" => {
            let sock = act.get("socket").and_then(|v| v.as_str()).unwrap_or("");
            let pid = act.get("pid").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            if process_birth(pid) != act.get("birth").and_then(|v| v.as_str()).unwrap_or("") {
                return Err("Neovim server was replaced".to_string());
            }
            let bufnr = act.get("bufnr").and_then(|v| v.as_i64()).unwrap_or(0);
            let cur = nvim_query(sock)?;
            if cur.get("pid").and_then(|v| v.as_i64()).unwrap_or(0) as i32 != pid {
                return Err("Neovim socket was replaced".to_string());
            }
            let expected_name = act.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let found = cur["buffers"].as_array().and_then(|arr| {
                arr.iter().find(|b| {
                    b.get("bufnr").and_then(|v| v.as_i64()) == Some(bufnr)
                        && canonical_path(b.get("name").and_then(|v| v.as_str()).unwrap_or(""))
                            == expected_name
                })
            });
            if found.is_none() {
                return Err("Neovim buffer closed or its number was reused".to_string());
            }
            let expr = format!(
                "luaeval('(function(b) local w=vim.fn.win_findbuf(b); if #w>0 then vim.api.nvim_set_current_win(w[1]); return 1 else vim.cmd(\"hide buffer \"..b); return 0 end end)(_A)',{})",
                bufnr
            );
            let out = Command::new("nvim")
                .args(["--server", sock, "--remote-expr", &expr])
                .stdin(Stdio::null())
                .output()
                .map_err(|_| "Neovim refused the buffer switch".to_string())?;
            if !out.status.success() {
                return Err("Neovim refused the buffer switch".to_string());
            }
            let used_existing = String::from_utf8_lossy(&out.stdout).trim() == "1";
            let route = act.get("route").and_then(|v| v.as_object());
            let rprov = route
                .and_then(|r| r.get("provider"))
                .and_then(|v| v.as_str())
                .unwrap_or("remote-ui");
            if rprov != "remote-ui" {
                let mut ract = route
                    .and_then(|r| r.get("activation"))
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                if used_existing {
                    if let Some(m) = ract.as_object_mut() {
                        m.insert("allow_new_client".to_string(), Value::Bool(false));
                    }
                }
                return activate_provider(rprov, &ract, procs, meta);
            }
            if !used_existing {
                return spawn_detached(&[
                    "omarchy-launch-terminal".to_string(),
                    "nvim".to_string(),
                    "--server".to_string(),
                    sock.to_string(),
                    "--remote-ui".to_string(),
                ]);
            }
            Ok(())
        }
        _ => Err("Thing provider is unavailable".to_string()),
    }
}

// ---------------------------------------------------------------- Native Fast Fuzzy/Substring Ranking (mirrors EverythingModel.js)

fn norm_text(s: &str) -> String {
    s.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn substring_score(haystack: &str, needle: &str) -> i64 {
    let hay = norm_text(haystack);
    let q = norm_text(needle);
    if q.is_empty() {
        return 0;
    }
    if hay.is_empty() {
        return -1;
    }
    if hay == q {
        return 12_000;
    }
    if let Some(pos) = hay.find(&q) {
        let diff = hay.len().saturating_sub(q.len()) as i64;
        if pos == 0 {
            return 9_000 - diff.min(1000);
        }
        return 7_000 - (pos as i64 * 16 + diff).min(2000);
    }
    // Bonus fuzzy subsequence fallback for CLI --search when no contiguous match
    let mut qi = q.chars().peekable();
    let mut gaps = 0i64;
    let mut last_hit = false;
    for ch in hay.chars() {
        if qi.peek() == Some(&ch) {
            qi.next();
            last_hit = true;
        } else if last_hit {
            gaps += 1;
            last_hit = false;
        }
    }
    if qi.peek().is_none() {
        (3_000 - gaps * 40).max(100)
    } else {
        -1
    }
}

fn rank_public_items(items: Vec<PublicThing>, query: &str) -> Vec<PublicThing> {
    let q = norm_text(query);
    let mut scored: Vec<(usize, i64, i64, i64, PublicThing)> = Vec::new();
    for item in items {
        let kind_ord = GROUP_ORDER
            .iter()
            .position(|&k| k == item.kind)
            .unwrap_or(1000);
        let (tier, score) = if q.is_empty() {
            (0, 0)
        } else {
            let ts = substring_score(&item.title, &q);
            if ts >= 0 {
                (3, ts)
            } else {
                let mut best_kw = substring_score(&item.context, &q);
                for term in &item.search_terms {
                    best_kw = best_kw.max(substring_score(term, &q));
                }
                if best_kw >= 0 {
                    (2, best_kw)
                } else {
                    let gs = substring_score(&item.kind, &q);
                    if gs >= 0 {
                        (1, gs)
                    } else {
                        continue;
                    }
                }
            }
        };
        let active_i = if item.active { 1 } else { 0 };
        let rec = (item.recency.clamp(-4000.0, 4000.0) * 100.0) as i64;
        scored.push((kind_ord, -(tier * 100_000 + score), -active_i, -rec, item));
    }
    scored.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.cmp(&b.2))
            .then_with(|| a.3.cmp(&b.3))
            .then_with(|| a.4.title.to_lowercase().cmp(&b.4.title.to_lowercase()))
    });
    scored.into_iter().map(|t| t.4).collect()
}

// ---------------------------------------------------------------- JSON-lines Server & Orchestrator

struct SharedState {
    registry: SnapshotRegistry,
    meta: ProviderMeta,
    warnings: BTreeMap<String, Vec<String>>,
}

struct Emitter {
    lock: Mutex<()>,
}

impl Emitter {
    fn new() -> Self {
        Self {
            lock: Mutex::new(()),
        }
    }

    fn send(&self, msg: &Value) {
        let _g = self.lock.lock();
        let stdout = io::stdout();
        let mut out = stdout.lock();
        let _ = serde_json::to_writer(&mut out, msg);
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    }
}

fn run_scan(
    request_id: String,
    scan_seq: u64,
    active_seq: Arc<AtomicU64>,
    state: Arc<Mutex<SharedState>>,
    emitter: Arc<Emitter>,
    emit_partials: bool,
) -> Value {
    let is_cancelled = || active_seq.load(Ordering::Acquire) != scan_seq;

    // Spawn /proc scan in background while Hyprland IPC runs immediately (<0.5 ms)!
    let t_procs = std::thread::spawn(ProcTable::read);

    // 1. Hyprland FIRST (sub-millisecond direct Unix socket!)
    let hypr_clients = match scan_hyprland(None) {
        Ok((scan, meta_clients)) => {
            if is_cancelled() {
                return Value::Null;
            }
            let public = {
                let mut st = state.lock().unwrap();
                st.meta.hypr_clients = meta_clients.clone();
                st.warnings.insert("hyprland".to_string(), scan.warnings.clone());
                st.registry.publish("hyprland", scan.items)
            };
            if emit_partials {
                emitter.send(&json!({
                    "version": PROTOCOL_VERSION,
                    "type": "snapshot",
                    "requestId": request_id,
                    "provider": "hyprland",
                    "full": false,
                    "items": public,
                    "warnings": scan.warnings,
                }));
            }
            Arc::new(meta_clients)
        }
        Err(err) => {
            if is_cancelled() {
                return Value::Null;
            }
            let warn = format!("Hyprland: {}", err);
            let public = {
                let mut st = state.lock().unwrap();
                st.warnings.insert("hyprland".to_string(), vec![warn.clone()]);
                st.registry.publish("hyprland", Vec::new())
            };
            if emit_partials {
                emitter.send(&json!({
                    "version": PROTOCOL_VERSION,
                    "type": "snapshot",
                    "requestId": request_id,
                    "provider": "hyprland",
                    "full": false,
                    "items": public,
                    "warnings": [warn.clone()],
                }));
                emitter.send(&json!({
                    "version": PROTOCOL_VERSION,
                    "type": "error",
                    "requestId": request_id,
                    "provider": "hyprland",
                    "message": warn,
                    "nonfatal": true,
                }));
            }
            let st = state.lock().unwrap();
            let full = build_full_snapshot(&request_id, &st);
            if emit_partials {
                emitter.send(&full);
            }
            return full;
        }
    };

    let procs = Arc::new(t_procs.join().unwrap_or_else(|_| ProcTable::read()));

    // 2. Run Kitty, Herdr, and tmux IN PARALLEL across worker threads!
    let (tx, rx) = std::sync::mpsc::channel::<(&'static str, ProviderScan)>();

    let p_k = Arc::clone(&procs);
    let h_k = Arc::clone(&hypr_clients);
    let st_k = Arc::clone(&state);
    let tx_k = tx.clone();
    let t_kitty = std::thread::spawn(move || {
        let (scan, surfaces) = scan_kitty(&p_k, &h_k);
        if let Ok(mut st) = st_k.lock() {
            st.meta.kitty_surfaces = surfaces;
        }
        let _ = tx_k.send(("kitty", scan));
    });

    let p_h = Arc::clone(&procs);
    let h_h = Arc::clone(&hypr_clients);
    let st_h = Arc::clone(&state);
    let tx_h = tx.clone();
    let t_herdr = std::thread::spawn(move || {
        let (scan, panes, sessions) = scan_herdr(&p_h, &h_h);
        if let Ok(mut st) = st_h.lock() {
            st.meta.herdr_panes = panes;
            st.meta.herdr_sessions = sessions;
        }
        let _ = tx_h.send(("herdr", scan));
    });

    let p_t = Arc::clone(&procs);
    let st_t = Arc::clone(&state);
    let tx_t = tx.clone();
    let t_tmux = std::thread::spawn(move || {
        let (scan, panes) = scan_tmux(&p_t);
        if let Ok(mut st) = st_t.lock() {
            st.meta.tmux_panes = panes;
        }
        let _ = tx_t.send(("tmux", scan));
    });
    drop(tx);

    for (prov, scan) in rx {
        if is_cancelled() {
            break;
        }
        let public = {
            let mut st = state.lock().unwrap();
            st.warnings.insert(prov.to_string(), scan.warnings.clone());
            st.registry.publish(prov, scan.items)
        };
        if emit_partials {
            emitter.send(&json!({
                "version": PROTOCOL_VERSION,
                "type": "snapshot",
                "requestId": request_id,
                "provider": prov,
                "full": false,
                "items": public,
                "warnings": scan.warnings,
            }));
        }
    }

    let _ = t_kitty.join();
    let _ = t_herdr.join();
    let _ = t_tmux.join();

    if is_cancelled() {
        return Value::Null;
    }

    // 3. Neovim AFTER container metadata (kitty/herdr/tmux) has landed so routes are exact!
    let meta_snap = state.lock().unwrap().meta.clone();
    let nvim_scan = scan_neovim(&procs, &meta_snap);
    if !is_cancelled() {
        let public = {
            let mut st = state.lock().unwrap();
            st.warnings
                .insert("neovim".to_string(), nvim_scan.warnings.clone());
            st.registry.publish("neovim", nvim_scan.items)
        };
        if emit_partials {
            emitter.send(&json!({
                "version": PROTOCOL_VERSION,
                "type": "snapshot",
                "requestId": request_id,
                "provider": "neovim",
                "full": false,
                "items": public,
                "warnings": nvim_scan.warnings,
            }));
        }
    }

    if is_cancelled() {
        return Value::Null;
    }

    let full = {
        let st = state.lock().unwrap();
        build_full_snapshot(&request_id, &st)
    };
    if emit_partials {
        emitter.send(&full);
    }
    full
}

fn build_full_snapshot(request_id: &str, st: &SharedState) -> Value {
    let all_warnings: Vec<String> = st
        .warnings
        .values()
        .flat_map(|v| v.iter().cloned())
        .collect();
    json!({
        "version": PROTOCOL_VERSION,
        "type": "snapshot",
        "requestId": request_id,
        "full": true,
        "items": st.registry.all_public(),
        "providers": st.registry.providers_map(),
        "warnings": all_warnings,
    })
}

fn looks_stale(msg: &str) -> bool {
    let l = msg.to_ascii_lowercase();
    [
        "stale",
        "closed",
        "replaced",
        "reused",
        "no longer",
        "disappeared",
        "not found",
    ]
    .iter()
    .any(|w| l.contains(w))
}

fn handle_activate(
    request_id: String,
    item_id: String,
    token: String,
    state: Arc<Mutex<SharedState>>,
    emitter: Arc<Emitter>,
    test_mode: bool,
) {
    let send_res = |ok: bool, stale: bool, msg: &str| {
        emitter.send(&json!({
            "version": PROTOCOL_VERSION,
            "type": "activation",
            "requestId": request_id,
            "itemId": item_id,
            "ok": ok,
            "stale": stale,
            "message": msg,
        }));
    };

    if test_mode {
        send_res(false, true, "Unknown test thing");
        return;
    }

    let reference = {
        let st = state.lock().unwrap();
        match st.registry.decode_reference(&item_id, &token) {
            Ok(r) => r,
            Err(e) => {
                send_res(false, true, &e);
                return;
            }
        }
    };
    let provider_name = reference
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let procs = ProcTable::read();
    // Refresh Hyprland liveness without bumping Hyprland generation
    if let Ok((_, h_meta)) = scan_hyprland(Some(&procs)) {
        if let Ok(mut st) = state.lock() {
            st.meta.hypr_clients = h_meta;
        }
    }

    let (mut row_opt, meta_snap) = {
        let st = state.lock().unwrap();
        let current = if st.registry.token_is_current(&reference) {
            st.registry.current(&provider_name, &item_id)
        } else {
            None
        };
        (current, st.meta.clone())
    };

    if row_opt.is_none() {
        row_opt = refresh_provider_for_activation(&provider_name, &item_id, &state, &procs);
    }
    let Some(row) = row_opt else {
        send_res(false, true, "That thing closed before it could be focused");
        return;
    };

    match activate_provider(&provider_name, &row.thing.activation, &procs, &meta_snap) {
        Ok(()) => send_res(true, false, ""),
        Err(first_err) => {
            if !looks_stale(&first_err) {
                send_res(false, false, &first_err);
                return;
            }
            let fresh_procs = ProcTable::read();
            if let Some(refreshed) =
                refresh_provider_for_activation(&provider_name, &item_id, &state, &fresh_procs)
            {
                let fresh_meta = state.lock().unwrap().meta.clone();
                match activate_provider(
                    &provider_name,
                    &refreshed.thing.activation,
                    &fresh_procs,
                    &fresh_meta,
                ) {
                    Ok(()) => send_res(true, false, ""),
                    Err(e) => send_res(false, looks_stale(&e), &e),
                }
            } else {
                send_res(false, true, "That thing closed before it could be focused");
            }
        }
    }
}

fn refresh_provider_for_activation(
    provider: &str,
    item_id: &str,
    state: &Arc<Mutex<SharedState>>,
    procs: &ProcTable,
) -> Option<PublishedThing> {
    let mut st = state.lock().unwrap();
    match provider {
        "hyprland" => {
            if let Ok((scan, h_meta)) = scan_hyprland(Some(procs)) {
                st.meta.hypr_clients = h_meta;
                st.registry.publish("hyprland", scan.items);
            }
        }
        "kitty" => {
            let hc = st.meta.hypr_clients.clone();
            let (scan, surfaces) = scan_kitty(procs, &hc);
            st.meta.kitty_surfaces = surfaces;
            st.registry.publish("kitty", scan.items);
        }
        "herdr" => {
            let hc = st.meta.hypr_clients.clone();
            let (scan, panes, sessions) = scan_herdr(procs, &hc);
            st.meta.herdr_panes = panes;
            st.meta.herdr_sessions = sessions;
            st.registry.publish("herdr", scan.items);
        }
        "tmux" => {
            let (scan, panes) = scan_tmux(procs);
            st.meta.tmux_panes = panes;
            st.registry.publish("tmux", scan.items);
        }
        "neovim" => {
            let m = st.meta.clone();
            let scan = scan_neovim(procs, &m);
            st.registry.publish("neovim", scan.items);
        }
        _ => return None,
    }
    st.registry.current(provider, item_id)
}

fn run_json_lines(test_mode: bool) -> i32 {
    let emitter = Arc::new(Emitter::new());
    let state = Arc::new(Mutex::new(SharedState {
        registry: SnapshotRegistry::new(),
        meta: ProviderMeta::default(),
        warnings: BTreeMap::new(),
    }));
    let active_seq = Arc::new(AtomicU64::new(0));

    // Handshake emitted in <1 ms!
    emitter.send(&json!({
        "version": PROTOCOL_VERSION,
        "type": "ready",
        "pluginVersion": PLUGIN_VERSION,
        "capabilities": {
            "partialSnapshots": true,
            "atspi": false,
            "ghosttyPalette": false,
        }
    }));

    let stdin = io::stdin();
    for line_res in stdin.lock().lines() {
        let Ok(line) = line_res else {
            break;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                emitter.send(&json!({
                    "version": PROTOCOL_VERSION,
                    "type": "error",
                    "requestId": "",
                    "message": "Malformed JSON request",
                    "nonfatal": true,
                }));
                continue;
            }
        };
        let Some(obj) = msg.as_object() else {
            emitter.send(&json!({
                "version": PROTOCOL_VERSION,
                "type": "error",
                "requestId": "",
                "message": "Request must be a JSON object",
                "nonfatal": true,
            }));
            continue;
        };
        let req_id = obj
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let ver = obj.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
        if ver != PROTOCOL_VERSION as u64 || req_id.is_empty() {
            emitter.send(&json!({
                "version": PROTOCOL_VERSION,
                "type": "error",
                "requestId": req_id,
                "message": "Unsupported protocol version or missing request id",
                "nonfatal": true,
            }));
            continue;
        }
        let req_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        match req_type {
            "scan" => {
                if test_mode {
                    emitter.send(&json!({
                        "version": PROTOCOL_VERSION,
                        "type": "snapshot",
                        "requestId": req_id,
                        "full": true,
                        "items": [],
                        "providers": {},
                        "warnings": [],
                    }));
                    continue;
                }
                let seq = active_seq.fetch_add(1, Ordering::AcqRel) + 1;
                let aseq = Arc::clone(&active_seq);
                let st = Arc::clone(&state);
                let em = Arc::clone(&emitter);
                std::thread::spawn(move || {
                    let _ = run_scan(req_id, seq, aseq, st, em, true);
                });
            }
            "activate" => {
                let item_id = obj
                    .get("itemId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let token = obj
                    .get("token")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if item_id.is_empty() || token.is_empty() {
                    emitter.send(&json!({
                        "version": PROTOCOL_VERSION,
                        "type": "error",
                        "requestId": req_id,
                        "message": "Activation requires itemId and token",
                        "nonfatal": true,
                    }));
                    continue;
                }
                let st = Arc::clone(&state);
                let em = Arc::clone(&emitter);
                std::thread::spawn(move || {
                    handle_activate(req_id, item_id, token, st, em, test_mode);
                });
            }
            "shutdown" => {
                active_seq.fetch_add(1, Ordering::AcqRel);
                break;
            }
            other => {
                emitter.send(&json!({
                    "version": PROTOCOL_VERSION,
                    "type": "error",
                    "requestId": req_id,
                    "message": format!("Unknown request type: {}", other),
                    "nonfatal": true,
                }));
            }
        }
    }
    0
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut json_lines = false;
    let mut snapshot = false;
    let mut search_query: Option<String> = None;
    let mut test_mode = std::env::var("EVERYTHING_TEST_MODE").as_deref() == Ok("1");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json-lines" => {
                json_lines = true;
                i += 1;
            }
            "--snapshot" => {
                snapshot = true;
                i += 1;
            }
            "--search" => {
                search_query = Some(args.get(i + 1).cloned().unwrap_or_default());
                i += 2;
            }
            "--test-mode" => {
                test_mode = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    if json_lines {
        std::process::exit(run_json_lines(test_mode));
    }

    if snapshot || search_query.is_some() {
        let emitter = Arc::new(Emitter::new());
        let state = Arc::new(Mutex::new(SharedState {
            registry: SnapshotRegistry::new(),
            meta: ProviderMeta::default(),
            warnings: BTreeMap::new(),
        }));
        let active_seq = Arc::new(AtomicU64::new(1));
        let mut full = run_scan("cli-1".to_string(), 1, active_seq, state, emitter, false);
        if let Some(q) = search_query {
            if let Some(items_val) = full.get("items") {
                if let Ok(items) = serde_json::from_value::<Vec<PublicThing>>(items_val.clone()) {
                    let ranked = rank_public_items(items, &q);
                    if let Some(obj) = full.as_object_mut() {
                        obj.insert("query".to_string(), Value::String(q));
                        obj.insert(
                            "items".to_string(),
                            serde_json::to_value(ranked).unwrap_or(Value::Array(vec![])),
                        );
                    }
                }
            }
        }
        let stdout = io::stdout();
        let mut lock = stdout.lock();
        let _ = serde_json::to_writer(&mut lock, &full);
        let _ = lock.write_all(b"\n");
        let _ = lock.flush();
        return;
    }

    eprintln!("Everything helper must be started with --json-lines, --snapshot, or --search <query>");
    std::process::exit(2);
}
