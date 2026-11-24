use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PSEUDO_FS: &[&str] = &[
    "tmpfs",
    "devtmpfs",
    "sysfs",
    "proc",
    "procfs",
    "cgroup",
    "cgroup2",
    "devpts",
    "securityfs",
    "pstore",
    "efivarfs",
    "bpf",
    "debugfs",
    "tracefs",
    "configfs",
    "fusectl",
    "hugetlbfs",
    "mqueue",
    "autofs",
    "binfmt_misc",
    "ramfs",
    "squashfs",
    "overlay",
    "nsfs",
    "rpc_pipefs",
    "selinuxfs",
    "fuse.portal",
    "fuse.gvfsd-fuse",
    "fuse.appimagelauncherfs",
];

const GROUP_ORDER: &[&str] = &["cpu", "gpu", "chassis", "drive", "wireless", "other"];

#[derive(Serialize)]
struct Snapshot {
    t: f64,
    host: String,
    uptime: f64,
    load: [f64; 3],
    ncpu: usize,
    procs: ProcsSummary,
    cpu: CpuSection,
    mem: MemSection,
    disks: Vec<DiskEntry>,
    nvme_temp: Option<f64>,
    sensors: SensorsSection,
    net: NetSection,
    gpus: Vec<GpuEntry>,
    processes: Vec<ProcEntry>,
}

#[derive(Serialize)]
struct ProcsSummary {
    total: usize,
    running: usize,
    threads: u64,
}

#[derive(Serialize)]
struct CpuSection {
    model: String,
    total: f64,
    cores: Vec<f64>,
    freq_mhz: Option<f64>,
    core_freq: Vec<Option<u64>>,
    temp: Option<f64>,
    core_temps: Vec<Option<f64>>,
    fans: Vec<FanShort>,
    power_w: Option<f64>,
}

#[derive(Clone, Serialize, Deserialize)]
struct FanShort {
    label: String,
    rpm: i64,
}

#[derive(Serialize)]
struct MemSection {
    total: u64,
    used: u64,
    available: u64,
    free: u64,
    cached: u64,
    buffers: u64,
    shared: u64,
    swap_total: u64,
    swap_used: u64,
    zswap: u64,
    swap_devices: Vec<SwapDevice>,
}

#[derive(Serialize)]
struct SwapDevice {
    name: String,
    #[serde(rename = "type")]
    swap_type: String,
}

#[derive(Serialize)]
struct DiskEntry {
    mount: String,
    source: String,
    fstype: String,
    total: u64,
    used: u64,
    free: u64,
    mounts: Vec<String>,
    read_bps: Option<f64>,
    write_bps: Option<f64>,
    temp: Option<f64>,
}

#[derive(Serialize)]
struct SensorsSection {
    temps: Vec<SensorTemp>,
    fans: Vec<SensorFan>,
}

#[derive(Clone, Serialize, Deserialize)]
struct SensorTemp {
    key: String,
    label: String,
    group: String,
    temp: f64,
    crit: Option<f64>,
    high: Option<f64>,
}

#[derive(Clone, Serialize, Deserialize)]
struct SensorFan {
    key: String,
    label: String,
    rpm: i64,
    max_rpm: Option<i64>,
}

#[derive(Serialize)]
struct NetSection {
    default: Option<String>,
    ifaces: Vec<NetIface>,
}

#[derive(Serialize)]
struct NetIface {
    name: String,
    up: bool,
    ip: Option<String>,
    wireless: bool,
    ssid: Option<String>,
    rx_bps: f64,
    tx_bps: f64,
    rx_total: u64,
    tx_total: u64,
}

#[derive(Serialize)]
struct GpuEntry {
    id: String,
    busy_estimated: bool,
    name: String,
    vendor: String,
    busy: Option<f64>,
    freq_mhz: Option<f64>,
    max_freq_mhz: Option<f64>,
    temp: Option<f64>,
    temp_shared: bool,
    power_w: Option<f64>,
    mem_used: Option<f64>,
    mem_total: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_unavailable: Option<bool>,
}

#[derive(Serialize)]
struct ProcEntry {
    pid: u32,
    ppid: i32,
    name: String,
    user: String,
    cpu: f64,
    mem: u64,
    threads: i64,
    state: String,
    cmd: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct SlowCache {
    updated_epoch: f64,
    ec_temps: Vec<SensorTemp>,
    ec_fans: Vec<SensorFan>,
    cpu_fans: Vec<FanShort>,
    nvme_temp: Option<f64>,
    drive_temps: HashMap<String, f64>,
    pci_names: HashMap<String, String>,
    ssids: HashMap<String, String>,
}

fn read_small(path: &Path) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let mut s = String::with_capacity(64);
    f.read_to_string(&mut s).ok()?;
    Some(s)
}

fn read_str(path: &Path) -> Option<String> {
    read_small(path).map(|s| s.trim().to_string())
}

fn read_i64(path: &Path) -> Option<i64> {
    let mut f = File::open(path).ok()?;
    let mut buf = [0u8; 64];
    let n = f.read(&mut buf).ok()?;
    let s = std::str::from_utf8(&buf[..n]).ok()?.trim();
    s.parse::<i64>().ok()
}

fn read_u64(path: &Path) -> Option<u64> {
    let mut f = File::open(path).ok()?;
    let mut buf = [0u8; 64];
    let n = f.read(&mut buf).ok()?;
    let s = std::str::from_utf8(&buf[..n]).ok()?.trim();
    s.parse::<u64>().ok()
}

fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn get_hostname() -> String {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc == 0 {
        if let Some(pos) = buf.iter().position(|&b| b == 0) {
            if let Ok(s) = std::str::from_utf8(&buf[..pos]) {
                if !s.is_empty() {
                    return s.to_string();
                }
            }
        }
    }
    read_str(Path::new("/etc/hostname")).unwrap_or_else(|| "localhost".to_string())
}

fn is_sane_temp(v: f64) -> bool {
    v > 1.0 && v < 200.0
}

fn is_slow_ec_hwmon(name: &str) -> bool {
    matches!(name, "dell_smm" | "dell_ddv" | "BAT0" | "AC" | "spd5118" | "nvme")
        || name.starts_with("ucsi_")
        || name.starts_with("hidpp_")
}

fn temp_group(devname: &str) -> &'static str {
    let lower = devname.to_ascii_lowercase();
    let base = lower.trim_end_matches(|c: char| c == '_' || c.is_ascii_digit());
    let matches_any = |list: &[&str]| list.iter().any(|&n| lower == n || base == n);
    if matches_any(&[
        "coretemp",
        "k10temp",
        "zenpower",
        "cpu_thermal",
        "soc_thermal",
        "cpu-thermal",
    ]) {
        "cpu"
    } else if matches_any(&["amdgpu", "i915", "xe", "nouveau", "radeon"]) {
        "gpu"
    } else if matches_any(&["nvme", "drivetemp"]) {
        "drive"
    } else if matches_any(&[
        "acpitz",
        "thinkpad",
        "asus",
        "pch_skylake",
        "pch_cannonlake",
    ]) {
        "chassis"
    } else if matches_any(&["iwlwifi", "mt7921", "ath11k", "ath12k"]) {
        "wireless"
    } else {
        "other"
    }
}

fn friendly_temp_label(devname: &str, label: &str, multi: bool) -> String {
    let l = label.trim().to_ascii_lowercase();
    let group = temp_group(devname);
    if group == "cpu" {
        if l.contains("package") || l.starts_with("tctl") || l.starts_with("tdie") {
            return "CPU package".to_string();
        }
        if l == "temp1" || l == "temp" {
            return "CPU".to_string();
        }
        return format!("CPU {}", label);
    }
    if group == "gpu" {
        if l == "temp1" || l == "edge" || l.is_empty() {
            return "GPU".to_string();
        }
        return format!("GPU {}", label);
    }
    if group == "drive" {
        if l.contains("composite") {
            return "Drive composite".to_string();
        }
        if let Some(rest) = l.strip_prefix("sensor") {
            return format!("Drive sensor {}", rest.trim());
        }
        return format!("Drive {}", label);
    }
    if group == "wireless" {
        return "Wi-Fi".to_string();
    }
    if group == "chassis" {
        let n = l.strip_prefix("temp").unwrap_or("");
        if multi && !n.is_empty() {
            return format!("Chassis {}", n);
        }
        return "Chassis".to_string();
    }
    if l.starts_with("temp") {
        return devname.to_string();
    }
    format!("{} {}", devname, label)
}

fn friendly_fan_label(devname: &str, label: &str) -> String {
    let l = label.trim().to_ascii_lowercase();
    let dl = devname.to_ascii_lowercase();
    if matches!(l.as_str(), "cpu_fan" | "cpu fan" | "fan1")
        && matches!(dl.as_str(), "asus" | "thinkpad" | "dell_smm")
    {
        return "CPU fan".to_string();
    }
    if matches!(l.as_str(), "gpu_fan" | "gpu fan") {
        return "GPU fan".to_string();
    }
    if let Some(rest) = l.strip_prefix("fan") {
        if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
            return format!("{} {}", devname, rest);
        }
    }
    label.replace('_', " ")
}

fn parse_temp_idx(filename: &str) -> u32 {
    filename
        .strip_prefix("temp")
        .and_then(|s| s.strip_suffix("_input"))
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(u32::MAX)
}

struct TempChannel {
    input_path: PathBuf,
    base_name: String,
    raw_label: String,
    friendly_label: String,
    crit: Option<f64>,
    high: Option<f64>,
    is_core: bool,
    core_id: Option<u32>,
}

struct FanChannel {
    input_path: PathBuf,
    base_name: String,
    friendly_label: String,
    max_rpm_path: PathBuf,
}

struct HwmonDev {
    name: String,
    dir: PathBuf,
    slow_ec: bool,
    temps: Vec<TempChannel>,
    fans: Vec<FanChannel>,
    has_fan_labels: bool,
    power_paths: Vec<PathBuf>,
}

struct ThermalZone {
    zone_type: String,
    temp_path: PathBuf,
    crit: Option<f64>,
}

struct Hwmon {
    devices: Vec<HwmonDev>,
    zones: Vec<ThermalZone>,
    coretemp_idx: Option<usize>,
    fan_dev_idx: Option<usize>,
    nvme_idx: Option<usize>,
}

impl Hwmon {
    fn discover(include_slow: bool) -> Self {
        let mut dirs: Vec<PathBuf> = fs::read_dir("/sys/class/hwmon")
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("hwmon"))
                    .unwrap_or(false)
            })
            .collect();
        dirs.sort();

        let mut devices = Vec::with_capacity(dirs.len());
        let mut seen_devices = HashSet::new();

        for dir in dirs {
            let fallback_name = dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("hwmon")
                .to_string();
            let name = read_str(&dir.join("name")).unwrap_or(fallback_name);
            seen_devices.insert(name.to_ascii_lowercase());
            let slow_ec = is_slow_ec_hwmon(&name);

            let mut temp_files: Vec<(u32, String, PathBuf)> = Vec::new();
            let mut fan_files: Vec<(String, PathBuf)> = Vec::new();
            let mut power_paths: Vec<PathBuf> = Vec::new();
            let mut has_fan_labels = false;

            if !slow_ec || include_slow {
                if let Ok(rd) = fs::read_dir(&dir) {
                    for entry in rd.flatten() {
                        let fname = entry.file_name();
                        let Some(s) = fname.to_str() else { continue };
                        if s.starts_with("temp") && s.ends_with("_input") {
                            temp_files.push((parse_temp_idx(s), s.to_string(), entry.path()));
                        } else if s.starts_with("fan") && s.ends_with("_input") {
                            fan_files.push((s.to_string(), entry.path()));
                        } else if s.starts_with("fan") && s.ends_with("_label") {
                            has_fan_labels = true;
                        } else if s.starts_with("power") && s.ends_with("_input") {
                            power_paths.push(entry.path());
                        }
                    }
                }
            } else {
                // Fast path: only inspect directory filenames for fan_dev selection (zero EC reads).
                if let Ok(rd) = fs::read_dir(&dir) {
                    for entry in rd.flatten() {
                        let fname = entry.file_name();
                        let Some(s) = fname.to_str() else { continue };
                        if s.starts_with("fan") && s.ends_with("_input") {
                            fan_files.push((s.to_string(), entry.path()));
                        } else if s.starts_with("fan") && s.ends_with("_label") {
                            has_fan_labels = true;
                        }
                    }
                }
            }
            temp_files.sort_by_key(|t| t.0);
            fan_files.sort_by(|a, b| a.0.cmp(&b.0));
            power_paths.sort();

            let multi = temp_files.len() > 1;
            let mut temps = Vec::with_capacity(temp_files.len());
            for (_, fname, input_path) in temp_files {
                let base_name = fname.trim_end_matches("_input").to_string();
                let label_path = dir.join(format!("{}_label", base_name));
                let raw_label = read_str(&label_path)
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| base_name.clone());
                let raw_lower = raw_label.to_ascii_lowercase();
                let is_core = raw_lower.starts_with("core ");
                let core_id = if raw_lower.starts_with("core") {
                    raw_lower[4..].trim().parse::<u32>().ok()
                } else {
                    None
                };
                let c = read_i64(&dir.join(format!("{}_crit", base_name)))
                    .filter(|&v| v > 1000 && v < 200_000)
                    .map(|v| v as f64 / 1000.0);
                let h = read_i64(&dir.join(format!("{}_max", base_name)))
                    .filter(|&v| v > 1000 && v < 200_000)
                    .map(|v| v as f64 / 1000.0);
                let friendly_label = friendly_temp_label(&name, &raw_label, multi);
                temps.push(TempChannel {
                    input_path,
                    base_name,
                    raw_label,
                    friendly_label,
                    crit: c,
                    high: h,
                    is_core,
                    core_id,
                });
            }

            let mut fans = Vec::with_capacity(fan_files.len());
            for (fname, input_path) in fan_files {
                let base_name = fname.trim_end_matches("_input").to_string();
                let raw = if !slow_ec || include_slow {
                    let label_path = dir.join(format!("{}_label", base_name));
                    read_str(&label_path)
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| base_name.clone())
                } else {
                    base_name.clone()
                };
                let friendly_label = friendly_fan_label(&name, &raw);
                let max_rpm_path = dir.join(format!("{}_max", base_name));
                fans.push(FanChannel {
                    input_path,
                    base_name,
                    friendly_label,
                    max_rpm_path,
                });
            }

            devices.push(HwmonDev {
                name,
                dir,
                slow_ec,
                temps,
                fans,
                has_fan_labels,
                power_paths,
            });
        }

        let coretemp_names = [
            "coretemp",
            "k10temp",
            "zenpower",
            "cpu_thermal",
            "soc_thermal",
            "cpu-thermal",
        ];
        let coretemp_idx = devices
            .iter()
            .position(|d| coretemp_names.contains(&d.name.as_str()));
        let nvme_idx = devices.iter().position(|d| d.name == "nvme");

        let mut fan_dev_idx = None;
        let mut best_score: (i32, i32) = (-1, -1);
        for (i, d) in devices.iter().enumerate() {
            if d.fans.is_empty() {
                continue;
            }
            let labelled = if d.has_fan_labels { 1 } else { 0 };
            let score = (labelled, d.fans.len() as i32);
            if score > best_score {
                best_score = score;
                fan_dev_idx = Some(i);
            }
        }

        // Thermal zones (ACPI EC — ~2ms each!) are discovered & sampled only on the slow background path.
        let mut zones = Vec::new();
        if include_slow {
            let mut zdirs: Vec<PathBuf> = fs::read_dir("/sys/class/thermal")
                .ok()
                .into_iter()
                .flatten()
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with("thermal_zone"))
                        .unwrap_or(false)
                })
                .collect();
            zdirs.sort();

            for z in zdirs {
                let Some(t) = read_str(&z.join("type")).filter(|s| !s.is_empty()) else {
                    continue;
                };
                let tl = t.to_ascii_lowercase();
                if tl.starts_with("int340") || tl.starts_with("x86_pkg_temp") {
                    continue;
                }
                let stripped = tl.trim_end_matches(|c: char| c == '_' || c.is_ascii_digit());
                if seen_devices.contains(&tl) || seen_devices.contains(stripped) {
                    continue;
                }
                let mut crit = None;
                let mut trips: Vec<PathBuf> = fs::read_dir(&z)
                    .ok()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .map(|n| n.starts_with("trip_point_") && n.ends_with("_type"))
                            .unwrap_or(false)
                    })
                    .collect();
                trips.sort();
                for tp in trips {
                    if read_str(&tp).as_deref() == Some("critical") {
                        if let Some(fname) = tp.file_name().and_then(|n| n.to_str()) {
                            let temp_tp =
                                z.join(format!("{}_temp", fname.trim_end_matches("_type")));
                            if let Some(c) =
                                read_i64(&temp_tp).filter(|&v| v > 1000 && v < 200_000)
                            {
                                crit = Some(c as f64 / 1000.0);
                                break;
                            }
                        }
                    }
                }
                zones.push(ThermalZone {
                    zone_type: t,
                    temp_path: z.join("temp"),
                    crit,
                });
            }
        }

        Self {
            devices,
            zones,
            coretemp_idx,
            fan_dev_idx,
            nvme_idx,
        }
    }

    fn read_coretemp(&self, core_ids: &[Option<u32>]) -> (Option<f64>, Vec<Option<f64>>) {
        let mut pkg_temp = None;
        let mut core_temp_by_id: HashMap<u32, f64> = HashMap::new();
        let mut max_temp: Option<f64> = None;

        if let Some(idx) = self.coretemp_idx {
            for ch in &self.devices[idx].temps {
                let Some(raw) = read_i64(&ch.input_path) else {
                    continue;
                };
                let v = raw as f64 / 1000.0;
                max_temp = Some(max_temp.map_or(v, |m| m.max(v)));
                let ll = ch.raw_label.to_ascii_lowercase();
                if pkg_temp.is_none()
                    && (ll.contains("package")
                        || ll.starts_with("tctl")
                        || ll.starts_with("tdie")
                        || ll == "temp1")
                {
                    pkg_temp = Some(v);
                }
                if let Some(cid) = ch.core_id {
                    core_temp_by_id.insert(cid, v);
                }
            }
        }

        let mut core_temps = Vec::new();
        if !core_temp_by_id.is_empty() {
            let mut any = false;
            core_temps.reserve(core_ids.len());
            for cid in core_ids {
                let t = cid.and_then(|id| core_temp_by_id.get(&id).copied());
                if t.is_some() {
                    any = true;
                }
                core_temps.push(t);
            }
            if !any {
                core_temps.clear();
            }
        }

        if pkg_temp.is_none() {
            pkg_temp = max_temp;
        }
        if pkg_temp.is_none() {
            for z in &self.zones {
                let tl = z.zone_type.to_ascii_lowercase();
                if tl.contains("cpu") || tl.contains("x86_pkg") || tl.contains("soc") {
                    if let Some(v) = read_i64(&z.temp_path) {
                        pkg_temp = Some(v as f64 / 1000.0);
                        break;
                    }
                }
            }
        }

        (pkg_temp, core_temps)
    }

    fn nvme_temp(&self) -> Option<f64> {
        let idx = self.nvme_idx?;
        for ch in &self.devices[idx].temps {
            if let Some(v) = read_i64(&ch.input_path) {
                return Some(v as f64 / 1000.0);
            }
        }
        None
    }

    fn read_hwmon_first_temp(&self, dir: &Path) -> Option<f64> {
        if let Some(dev) = self.devices.iter().find(|d| d.dir == dir) {
            for ch in &dev.temps {
                if let Some(v) = read_i64(&ch.input_path) {
                    return Some(v as f64 / 1000.0);
                }
            }
        }
        None
    }

    fn read_hwmon_power_w(&self, dir: &Path) -> Option<f64> {
        if let Some(dev) = self.devices.iter().find(|d| d.dir == dir) {
            for p in &dev.power_paths {
                if let Some(v) = read_i64(p) {
                    return Some(v as f64 / 1_000_000.0);
                }
            }
        }
        None
    }

    fn read_fast_sensors(&self, slow: &SlowCache) -> (Vec<SensorTemp>, Vec<SensorFan>, Vec<FanShort>) {
        let mut temps = Vec::with_capacity(32);
        let mut fans = Vec::with_capacity(8);

        for dev in &self.devices {
            if dev.slow_ec {
                continue;
            }
            let group = temp_group(&dev.name).to_string();
            for ch in &dev.temps {
                if ch.is_core {
                    continue;
                }
                let Some(raw) = read_i64(&ch.input_path) else {
                    continue;
                };
                let v = raw as f64 / 1000.0;
                if !is_sane_temp(v) {
                    continue;
                }
                temps.push(SensorTemp {
                    key: format!("{}/{}", dev.name, ch.base_name),
                    label: ch.friendly_label.clone(),
                    group: group.clone(),
                    temp: v,
                    crit: ch.crit,
                    high: ch.high,
                });
            }
            for fch in &dev.fans {
                if let Some(rpm) = read_i64(&fch.input_path).filter(|&v| v >= 0) {
                    fans.push(SensorFan {
                        key: format!("{}/{}", dev.name, fch.base_name),
                        label: fch.friendly_label.clone(),
                        rpm,
                        max_rpm: read_i64(&fch.max_rpm_path),
                    });
                }
            }
        }

        // Merge cached slow EC temps & fans (dell_smm / dell_ddv) with zero blocking!
        temps.extend(slow.ec_temps.iter().cloned());
        fans.extend(slow.ec_fans.iter().cloned());

        for z in &self.zones {
            let Some(raw) = read_i64(&z.temp_path) else {
                continue;
            };
            let v = raw as f64 / 1000.0;
            if !is_sane_temp(v) {
                continue;
            }
            temps.push(SensorTemp {
                key: format!("zone/{}", z.zone_type),
                label: z.zone_type.clone(),
                group: temp_group(&z.zone_type).to_string(),
                temp: v,
                crit: z.crit,
                high: None,
            });
        }

        temps.sort_by(|a, b| {
            let ga = GROUP_ORDER
                .iter()
                .position(|&g| g == a.group)
                .unwrap_or(99);
            let gb = GROUP_ORDER
                .iter()
                .position(|&g| g == b.group)
                .unwrap_or(99);
            ga.cmp(&gb).then_with(|| a.label.cmp(&b.label))
        });

        let cpu_fans = if let Some(idx) = self.fan_dev_idx {
            let dev = &self.devices[idx];
            if dev.slow_ec {
                slow.cpu_fans.clone()
            } else {
                dev.fans
                    .iter()
                    .filter_map(|fch| {
                        let rpm = read_i64(&fch.input_path)?;
                        Some(FanShort {
                            label: fch.friendly_label.clone(),
                            rpm,
                        })
                    })
                    .collect()
            }
        } else {
            Vec::new()
        };

        (temps, fans, cpu_fans)
    }

    fn sample_slow_ec(&self) -> (Vec<SensorTemp>, Vec<SensorFan>, Vec<FanShort>, Option<f64>) {
        let mut ec_temps = Vec::new();
        let mut ec_fans = Vec::new();
        let mut cpu_fans = Vec::new();

        for (i, dev) in self.devices.iter().enumerate() {
            if !dev.slow_ec {
                continue;
            }
            let group = temp_group(&dev.name).to_string();
            for ch in &dev.temps {
                if ch.is_core {
                    continue;
                }
                let Some(raw) = read_i64(&ch.input_path) else {
                    continue;
                };
                let v = raw as f64 / 1000.0;
                if !is_sane_temp(v) {
                    continue;
                }
                ec_temps.push(SensorTemp {
                    key: format!("{}/{}", dev.name, ch.base_name),
                    label: ch.friendly_label.clone(),
                    group: group.clone(),
                    temp: v,
                    crit: ch.crit,
                    high: ch.high,
                });
            }
            for fch in &dev.fans {
                if let Some(rpm) = read_i64(&fch.input_path).filter(|&v| v >= 0) {
                    let max_rpm = read_i64(&fch.max_rpm_path);
                    ec_fans.push(SensorFan {
                        key: format!("{}/{}", dev.name, fch.base_name),
                        label: fch.friendly_label.clone(),
                        rpm,
                        max_rpm,
                    });
                    if Some(i) == self.fan_dev_idx {
                        cpu_fans.push(FanShort {
                            label: fch.friendly_label.clone(),
                            rpm,
                        });
                    }
                }
            }
        }
        // Also sample ACPI thermal zones on the slow background thread
        for z in &self.zones {
            let Some(raw) = read_i64(&z.temp_path) else {
                continue;
            };
            let v = raw as f64 / 1000.0;
            if !is_sane_temp(v) {
                continue;
            }
            ec_temps.push(SensorTemp {
                key: format!("zone/{}", z.zone_type),
                label: z.zone_type.clone(),
                group: temp_group(&z.zone_type).to_string(),
                temp: v,
                crit: z.crit,
                high: None,
            });
        }
        let nvme_temp = self.nvme_temp();
        (ec_temps, ec_fans, cpu_fans, nvme_temp)
    }
}

fn slow_cache_path() -> PathBuf {
    let runtime = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("/run/user/{}", unsafe { libc::getuid() }));
    PathBuf::from(runtime).join("vitalsd-ec-cache.json")
}

fn load_slow_cache() -> SlowCache {
    let path = slow_cache_path();
    let Ok(bytes) = fs::read(&path) else {
        return SlowCache::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

fn save_slow_cache(cache: &SlowCache) {
    let path = slow_cache_path();
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    if let Ok(bytes) = serde_json::to_vec(cache) {
        use std::os::unix::fs::OpenOptionsExt;
        if let Ok(mut f) = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
        {
            if f.write_all(&bytes).is_ok() {
                let _ = fs::rename(&tmp, &path);
                return;
            }
        }
        let _ = fs::remove_file(&tmp);
    }
}

fn sample_wifi_ssids() -> HashMap<String, String> {
    let mut ssids = HashMap::new();
    let Ok(rd) = fs::read_dir("/sys/class/net") else {
        return ssids;
    };
    for entry in rd.flatten() {
        let iface_path = entry.path();
        if !iface_path.join("wireless").exists() {
            continue;
        }
        let Some(iface) = entry.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        if let Ok(out) = Command::new("iw")
            .args(["dev", &iface, "link"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        {
            if let Ok(text) = std::str::from_utf8(&out.stdout) {
                for line in text.lines() {
                    let trimmed = line.trim();
                    if let Some(rest) = trimmed.strip_prefix("SSID:") {
                        let ssid = rest.trim();
                        if !ssid.is_empty() {
                            ssids.insert(iface.clone(), ssid.to_string());
                        }
                        break;
                    }
                }
            }
        }
    }
    ssids
}

fn refresh_slow_cache_once(hwmon: &Hwmon, prev_pci_names: &HashMap<String, String>) -> SlowCache {
    let (ec_temps, ec_fans, cpu_fans, nvme_temp) = hwmon.sample_slow_ec();
    let ssids = sample_wifi_ssids();
    let mut dt = DriveTemps::new();
    let mut drive_temps = HashMap::new();
    for m in read_mounts() {
        if let Some(ref dev) = m.dev {
            if let Some(t) = dt.temp(dev) {
                drive_temps.insert(dev.clone(), t);
            }
        }
    }
    let pci_names = if prev_pci_names.is_empty() {
        Gpus::discover_pci_names_map()
    } else {
        prev_pci_names.clone()
    };
    let cache = SlowCache {
        updated_epoch: now_epoch(),
        ec_temps,
        ec_fans,
        cpu_fans,
        nvme_temp,
        drive_temps,
        pci_names,
        ssids,
    };
    save_slow_cache(&cache);
    cache
}

// ---------------------------------------------------------------- CPU

fn cpu_times() -> HashMap<String, (u64, u64)> {
    let mut out = HashMap::with_capacity(32);
    let Ok(data) = fs::read_to_string("/proc/stat") else {
        return out;
    };
    for line in data.lines() {
        if !line.starts_with("cpu") {
            continue;
        }
        let mut parts = line.split_ascii_whitespace();
        let Some(name) = parts.next() else { continue };
        let mut vals = [0u64; 12];
        let mut count = 0usize;
        let mut total = 0u64;
        for p in parts {
            if let Ok(v) = p.parse::<u64>() {
                if count < vals.len() {
                    vals[count] = v;
                }
                count += 1;
                total = total.saturating_add(v);
            }
        }
        if count >= 4 {
            let idle = vals[3].saturating_add(if count > 4 { vals[4] } else { 0 });
            out.insert(name.to_string(), (idle, total));
        }
    }
    out
}

fn cpu_percentages(
    prev: &HashMap<String, (u64, u64)>,
    cur: &HashMap<String, (u64, u64)>,
) -> HashMap<String, f64> {
    let mut res = HashMap::with_capacity(cur.len());
    for (name, &(idle, total)) in cur {
        let Some(&(pidle, ptotal)) = prev.get(name) else {
            res.insert(name.clone(), 0.0);
            continue;
        };
        let dt = total.saturating_sub(ptotal);
        let di = idle.saturating_sub(pidle);
        let pct = if dt == 0 {
            0.0
        } else {
            ((dt.saturating_sub(di)) as f64 * 100.0 / dt as f64).clamp(0.0, 100.0)
        };
        res.insert(name.clone(), pct);
    }
    res
}

fn cpu_model() -> String {
    if let Ok(data) = fs::read_to_string("/proc/cpuinfo") {
        for line in data.lines() {
            if line.starts_with("model name") {
                if let Some((_, rhs)) = line.split_once(':') {
                    let mut name = rhs.trim().to_string();
                    for junk in ["(R)", "(TM)", "(tm)", "CPU", "Processor"] {
                        name = name.replace(junk, "");
                    }
                    let collapsed: String = name
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ");
                    let clean = collapsed
                        .split_once('@')
                        .map(|(head, _)| head.trim())
                        .unwrap_or(collapsed.as_str());
                    return clean.to_string();
                }
            }
        }
    }
    read_str(Path::new("/sys/firmware/devicetree/base/model")).unwrap_or_else(|| "CPU".to_string())
}

fn cpu_freqs(freq_paths: &[PathBuf]) -> Vec<Option<u64>> {
    let mut freqs = Vec::with_capacity(freq_paths.len());
    let mut any = false;
    for p in freq_paths {
        let v = read_u64(p).filter(|&khz| khz > 0).map(|khz| khz / 1000);
        if v.is_some() {
            any = true;
        }
        freqs.push(v);
    }
    if !any {
        freqs.clear();
        if let Ok(data) = fs::read_to_string("/proc/cpuinfo") {
            for line in data.lines() {
                if line.starts_with("cpu MHz") {
                    if let Some((_, rhs)) = line.split_once(':') {
                        if let Ok(v) = rhs.trim().parse::<f64>() {
                            freqs.push(Some(v as u64));
                        }
                    }
                }
            }
        }
    }
    freqs
}

struct Rapl {
    path: Option<PathBuf>,
    prev: Option<(u64, Instant)>,
}

impl Rapl {
    fn new() -> Self {
        let candidates = [
            "/sys/class/powercap/intel-rapl:0/energy_uj",
            "/sys/class/powercap/intel-rapl-mmio:0/energy_uj",
        ];
        let path = candidates
            .iter()
            .map(PathBuf::from)
            .find(|p| read_u64(p).is_some());
        Self { path, prev: None }
    }

    fn watts(&mut self, now: Instant) -> Option<f64> {
        let path = self.path.as_ref()?;
        let v = read_u64(path)?;
        let mut w = None;
        if let Some((pv, pt)) = self.prev {
            let dt = now.duration_since(pt).as_secs_f64();
            if dt > 0.0 && v >= pv {
                w = Some((v - pv) as f64 / 1_000_000.0 / dt);
            }
        }
        self.prev = Some((v, now));
        w
    }
}

// ---------------------------------------------------------------- Memory

fn read_meminfo() -> MemSection {
    let mut total = 0u64;
    let mut avail = 0u64;
    let mut free = 0u64;
    let mut cached_part = 0u64;
    let mut sreclaimable = 0u64;
    let mut buffers = 0u64;
    let mut shared = 0u64;
    let mut swap_total = 0u64;
    let mut swap_free = 0u64;
    let mut zswap = 0u64;

    if let Ok(data) = fs::read_to_string("/proc/meminfo") {
        for line in data.lines() {
            let Some((k, rest)) = line.split_once(':') else {
                continue;
            };
            let Some(val_str) = rest.split_ascii_whitespace().next() else {
                continue;
            };
            let Ok(kb) = val_str.parse::<u64>() else {
                continue;
            };
            let bytes = kb.saturating_mul(1024);
            match k {
                "MemTotal" => total = bytes,
                "MemAvailable" => avail = bytes,
                "MemFree" => free = bytes,
                "Cached" => cached_part = bytes,
                "SReclaimable" => sreclaimable = bytes,
                "Buffers" => buffers = bytes,
                "Shmem" => shared = bytes,
                "SwapTotal" => swap_total = bytes,
                "SwapFree" => swap_free = bytes,
                "Zswapped" => zswap = bytes,
                _ => {}
            }
        }
    }

    let mut swap_devices = Vec::new();
    if let Ok(swaps) = fs::read_to_string("/proc/swaps") {
        for line in swaps.lines().skip(1) {
            let mut p = line.split_ascii_whitespace();
            let (Some(name), Some(st)) = (p.next(), p.next()) else {
                continue;
            };
            if p.next().is_some() {
                swap_devices.push(SwapDevice {
                    name: name.to_string(),
                    swap_type: st.to_string(),
                });
            }
        }
    }

    MemSection {
        total,
        used: total.saturating_sub(avail),
        available: avail,
        free,
        cached: cached_part.saturating_add(sreclaimable),
        buffers,
        shared,
        swap_total,
        swap_used: swap_total.saturating_sub(swap_free),
        zswap,
        swap_devices,
    }
}

// ---------------------------------------------------------------- Disks

struct DriveTemps {
    base: HashMap<String, Option<String>>,
    path: HashMap<String, Option<PathBuf>>,
}

impl DriveTemps {
    fn new() -> Self {
        Self {
            base: HashMap::new(),
            path: HashMap::new(),
        }
    }

    fn resolve_base(dev: &str, depth: usize) -> Option<String> {
        if dev.is_empty() || depth > 4 {
            return None;
        }
        let slaves_dir = format!("/sys/block/{}/slaves", dev);
        if let Ok(rd) = fs::read_dir(&slaves_dir) {
            let mut slaves: Vec<String> = rd
                .flatten()
                .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
                .collect();
            slaves.sort();
            if let Some(first) = slaves.first() {
                return Self::resolve_base(first, depth + 1);
            }
        }
        let part_marker = format!("/sys/class/block/{}/partition", dev);
        if Path::new(&part_marker).exists() {
            if let Ok(real) = fs::canonicalize(format!("/sys/class/block/{}", dev)) {
                if let Some(parent) = real
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                {
                    if !parent.is_empty() && parent != dev {
                        return Self::resolve_base(parent, depth + 1);
                    }
                }
            }
            return None;
        }
        if Path::new(&format!("/sys/block/{}", dev)).is_dir() {
            Some(dev.to_string())
        } else {
            None
        }
    }

    fn resolve_path(base: &str) -> Option<PathBuf> {
        for sub in [
            format!("/sys/block/{}/device", base),
            format!("/sys/block/{}/device/device", base),
        ] {
            let mut hw_dirs: Vec<PathBuf> = fs::read_dir(&sub)
                .ok()
                .into_iter()
                .flatten()
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with("hwmon"))
                        .unwrap_or(false)
                })
                .collect();
            hw_dirs.sort();
            for hw in hw_dirs {
                let mut temps: Vec<PathBuf> = fs::read_dir(&hw)
                    .ok()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .map(|n| n.starts_with("temp") && n.ends_with("_input"))
                            .unwrap_or(false)
                    })
                    .collect();
                temps.sort();
                if let Some(first) = temps.into_iter().next() {
                    return Some(first);
                }
            }
        }
        None
    }

    fn temp(&mut self, dev: &str) -> Option<f64> {
        let base = self
            .base
            .entry(dev.to_string())
            .or_insert_with(|| Self::resolve_base(dev, 0))
            .clone()?;
        let p = self
            .path
            .entry(base.clone())
            .or_insert_with(|| Self::resolve_path(&base))
            .as_ref()?;
        let raw = read_i64(p)?;
        let v = raw as f64 / 1000.0;
        if is_sane_temp(v) {
            Some(v)
        } else {
            None
        }
    }
}

fn diskstats() -> HashMap<String, (u64, u64)> {
    let mut out = HashMap::with_capacity(32);
    let Ok(data) = fs::read_to_string("/proc/diskstats") else {
        return out;
    };
    for line in data.lines() {
        let p: Vec<&str> = line.split_ascii_whitespace().collect();
        if p.len() < 14 {
            continue;
        }
        let Ok(r_sec) = p[5].parse::<u64>() else {
            continue;
        };
        let Ok(w_sec) = p[9].parse::<u64>() else {
            continue;
        };
        out.insert(
            p[2].to_string(),
            (r_sec.saturating_mul(512), w_sec.saturating_mul(512)),
        );
    }
    out
}

fn dev_for_source(source: &str) -> Option<String> {
    if !source.starts_with("/dev/") {
        return None;
    }
    let meta = fs::metadata(source).ok()?;
    let rdev = meta.rdev();
    let major = libc::major(rdev);
    let minor = libc::minor(rdev);
    let uevent = read_small(Path::new(&format!("/sys/dev/block/{}:{}/uevent", major, minor)))?;
    for line in uevent.lines() {
        if let Some(name) = line.strip_prefix("DEVNAME=") {
            return Some(name.trim().to_string());
        }
    }
    None
}

struct MountInfo {
    mount: String,
    source: String,
    fstype: String,
    total: u64,
    used: u64,
    free: u64,
    mounts: Vec<String>,
    dev: Option<String>,
}

fn read_mounts() -> Vec<MountInfo> {
    let mut seen: HashMap<(String, u64, u64), usize> = HashMap::new();
    let mut order: Vec<MountInfo> = Vec::new();
    let Ok(data) = fs::read_to_string("/proc/self/mounts") else {
        return order;
    };

    for line in data.lines() {
        let mut p = line.split_ascii_whitespace();
        let (Some(source), Some(raw_target), Some(fstype)) = (p.next(), p.next(), p.next()) else {
            continue;
        };
        let target = raw_target.replace("\\040", " ");
        if PSEUDO_FS.contains(&fstype)
            || (fstype.starts_with("fuse.") && !fstype.contains("sshfs"))
        {
            continue;
        }
        let valid_src = source.starts_with("/dev/")
            || source.contains(':')
            || source.starts_with("//")
            || matches!(fstype, "nfs" | "nfs4" | "cifs" | "smb3");
        if !valid_src {
            continue;
        }
        if [
            "/proc",
            "/sys",
            "/dev",
            "/run/",
            "/snap/",
            "/var/lib/docker",
            "/var/lib/containers",
        ]
        .iter()
        .any(|prefix| target.starts_with(prefix))
        {
            continue;
        }
        let Ok(c_target) = std::ffi::CString::new(target.as_str()) else {
            continue;
        };
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c_target.as_ptr(), &mut st) } != 0 {
            continue;
        }
        let frsize = st.f_frsize as u64;
        let total = (st.f_blocks as u64).saturating_mul(frsize);
        if total == 0 {
            continue;
        }
        let free = (st.f_bavail as u64).saturating_mul(frsize);
        let used = (st.f_blocks as u64)
            .saturating_sub(st.f_bfree as u64)
            .saturating_mul(frsize);
        let key = (source.to_string(), total, used);
        if let Some(&idx) = seen.get(&key) {
            order[idx].mounts.push(target);
            continue;
        }
        let idx = order.len();
        seen.insert(key, idx);
        order.push(MountInfo {
            mount: target,
            source: source.to_string(),
            fstype: fstype.to_string(),
            total,
            used,
            free,
            mounts: Vec::new(),
            dev: dev_for_source(source),
        });
    }

    order.sort_by(|a, b| (a.mount != "/").cmp(&(b.mount != "/")).then_with(|| a.mount.cmp(&b.mount)));
    order
}

// ---------------------------------------------------------------- Network

fn net_dev() -> HashMap<String, (u64, u64)> {
    let mut out = HashMap::with_capacity(16);
    let Ok(data) = fs::read_to_string("/proc/net/dev") else {
        return out;
    };
    for line in data.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let p: Vec<&str> = rest.split_ascii_whitespace().collect();
        if p.len() >= 9 {
            if let (Ok(rx), Ok(tx)) = (p[0].parse::<u64>(), p[8].parse::<u64>()) {
                out.insert(name.trim().to_string(), (rx, tx));
            }
        }
    }
    out
}

fn default_iface() -> Option<String> {
    let data = fs::read_to_string("/proc/net/route").ok()?;
    for line in data.lines().skip(1) {
        let mut p = line.split_ascii_whitespace();
        let (Some(iface), Some(dest)) = (p.next(), p.next()) else {
            continue;
        };
        if dest == "00000000" {
            return Some(iface.to_string());
        }
    }
    None
}

fn iface_ips() -> HashMap<String, String> {
    let mut ips = HashMap::new();
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return ips;
    }
    let mut cur = addrs;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        if !ifa.ifa_name.is_null() && !ifa.ifa_addr.is_null() {
            let family = unsafe { (*ifa.ifa_addr).sa_family as i32 };
            if family == libc::AF_INET {
                let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
                    .to_string_lossy()
                    .into_owned();
                let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)).to_string();
                ips.entry(name).or_insert(ip);
            }
        }
        cur = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(addrs) };
    ips
}

// ---------------------------------------------------------------- GPUs (ZERO lspci, ZERO D3cold wake!)

struct GpuCard {
    path: PathBuf,
    dev: PathBuf,
    vendor: String,
    pci: String,
    name: String,
    hwmon: Option<PathBuf>,
    gt_dir: Option<PathBuf>,
    xe_freq_dir: Option<PathBuf>,
}

struct Gpus {
    cards: Vec<GpuCard>,
    rc6_prev: HashMap<PathBuf, (u64, Instant)>,
    nvidia_smi: Option<PathBuf>,
}

fn clean_pci_name(raw: &str) -> String {
    let mut name = raw.to_string();
    for junk in ["Corporation", "Advanced Micro Devices, Inc.", "[AMD/ATI]"] {
        name = name.replace(junk, "");
    }
    name.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn lookup_pci_ids(targets: &[(String, String)]) -> HashMap<(String, String), String> {
    let mut found = HashMap::new();
    if targets.is_empty() {
        return found;
    }
    let target_vendors: HashSet<&str> = targets.iter().map(|(v, _)| v.as_str()).collect();
    let target_set: HashSet<(&str, &str)> = targets
        .iter()
        .map(|(v, d)| (v.as_str(), d.as_str()))
        .collect();

    let pci_ids_path = ["/usr/share/hwdata/pci.ids", "/usr/share/misc/pci.ids"]
        .iter()
        .map(Path::new)
        .find(|p| p.exists());
    let Some(path) = pci_ids_path else {
        return found;
    };
    let Ok(bytes) = fs::read(path) else {
        return found;
    };

    let mut active_vendor: Option<&str> = None;
    for line in bytes.split(|&b| b == b'\n') {
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        if line[0] == b'\t' {
            if let Some(v) = active_vendor {
                if line.len() > 6 && line[1] != b'\t' {
                    if let Ok(dev_hex) = std::str::from_utf8(&line[1..5]) {
                        let dev_lc = dev_hex.to_ascii_lowercase();
                        if target_set.contains(&(v, dev_lc.as_str())) {
                            if let Ok(desc) = std::str::from_utf8(&line[5..]) {
                                found.insert((v.to_string(), dev_lc), clean_pci_name(desc.trim()));
                                if found.len() == target_set.len() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        } else if line.len() >= 4 && line[0].is_ascii_hexdigit() {
            if let Ok(v_hex) = std::str::from_utf8(&line[0..4]) {
                let mut matched = None;
                for &tv in &target_vendors {
                    if tv.eq_ignore_ascii_case(v_hex) {
                        matched = Some(tv);
                        break;
                    }
                }
                active_vendor = matched;
            } else {
                active_vendor = None;
            }
        } else {
            active_vendor = None;
        }
    }
    found
}

fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let cand = dir.join(bin);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

impl Gpus {
    fn discover_pci_names_map() -> HashMap<String, String> {
        let mut targets = Vec::new();
        if let Ok(rd) = fs::read_dir("/sys/class/drm") {
            for entry in rd.flatten() {
                let fname = entry.file_name();
                let Some(n) = fname.to_str() else { continue };
                if !(n.starts_with("card")
                    && !n.contains('-')
                    && n.len() > 4
                    && n[4..].bytes().all(|b| b.is_ascii_digit()))
                {
                    continue;
                }
                let dev = entry.path().join("device");
                let Some(vendor) = read_str(&dev.join("vendor")) else {
                    continue;
                };
                let device = read_str(&dev.join("device")).unwrap_or_default();
                let vh = vendor.trim_start_matches("0x").to_ascii_lowercase();
                let dh = device.trim_start_matches("0x").to_ascii_lowercase();
                if vh.len() == 4 && dh.len() == 4 {
                    targets.push((vh, dh));
                }
            }
        }
        lookup_pci_ids(&targets)
            .into_iter()
            .map(|((v, d), name)| (format!("{}:{}", v, d), name))
            .collect()
    }

    fn discover(cached_pci: &HashMap<String, String>) -> Self {
        let mut card_paths: Vec<PathBuf> = fs::read_dir("/sys/class/drm")
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| {
                        n.starts_with("card")
                            && !n.contains('-')
                            && n[4..].bytes().all(|b| b.is_ascii_digit())
                            && n.len() > 4
                    })
                    .unwrap_or(false)
            })
            .collect();
        card_paths.sort();

        struct RawCard {
            path: PathBuf,
            dev: PathBuf,
            vendor: String,
            vendor_hex: String,
            device_hex: String,
            pci: String,
            hwmon: Option<PathBuf>,
            gt_dir: Option<PathBuf>,
            xe_freq_dir: Option<PathBuf>,
        }

        let mut raw_cards = Vec::new();
        let mut pci_targets = Vec::new();

        for card in card_paths {
            let dev = card.join("device");
            let Some(vendor) = read_str(&dev.join("vendor")) else {
                continue;
            };
            let device = read_str(&dev.join("device")).unwrap_or_default();
            let pci = fs::canonicalize(&dev)
                .ok()
                .and_then(|p| p.file_name().and_then(|n| n.to_str()).map(|s| s.to_string()))
                .unwrap_or_default();
            let vendor_hex = vendor.trim_start_matches("0x").to_ascii_lowercase();
            let device_hex = device.trim_start_matches("0x").to_ascii_lowercase();
            if vendor_hex.len() == 4 && device_hex.len() == 4 {
                pci_targets.push((vendor_hex.clone(), device_hex.clone()));
            }
            // Do not traverse NVIDIA hwmon while suspended; NVIDIA telemetry comes from nvidia-smi only when active.
            let hwmon = if vendor == "0x10de" {
                None
            } else {
                fs::read_dir(dev.join("hwmon"))
                    .ok()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .find(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .map(|n| n.starts_with("hwmon"))
                            .unwrap_or(false)
                    })
            };

            let gt_dir = fs::read_dir(card.join("gt"))
                .ok()
                .into_iter()
                .flatten()
                .filter_map(|e| e.ok().map(|e| e.path()))
                .find(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with("gt"))
                        .unwrap_or(false)
                });

            let mut xe_freq_dir = None;
            if gt_dir.is_none() && vendor == "0x8086" {
                if let Ok(tiles) = fs::read_dir(&dev) {
                    for tile in tiles.flatten() {
                        let tname = tile.file_name();
                        if tname.to_str().map(|s| s.starts_with("tile")).unwrap_or(false) {
                            if let Ok(gts) = fs::read_dir(tile.path()) {
                                for gt in gts.flatten() {
                                    if gt
                                        .file_name()
                                        .to_str()
                                        .map(|s| s.starts_with("gt"))
                                        .unwrap_or(false)
                                    {
                                        let cand = gt.path().join("freq0");
                                        if cand.is_dir() {
                                            xe_freq_dir = Some(cand);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        if xe_freq_dir.is_some() {
                            break;
                        }
                    }
                }
            }

            raw_cards.push(RawCard {
                path: card,
                dev,
                vendor,
                vendor_hex,
                device_hex,
                pci,
                hwmon,
                gt_dir,
                xe_freq_dir,
            });
        }

        let missing_targets: Vec<(String, String)> = pci_targets
            .iter()
            .filter(|(v, d)| !cached_pci.contains_key(&format!("{}:{}", v, d)))
            .cloned()
            .collect();
        let looked_up = lookup_pci_ids(&missing_targets);
        let cards = raw_cards
            .into_iter()
            .map(|c| {
                let key = format!("{}:{}", c.vendor_hex, c.device_hex);
                let name = cached_pci
                    .get(&key)
                    .cloned()
                    .or_else(|| looked_up.get(&(c.vendor_hex, c.device_hex)).cloned())
                    .unwrap_or_else(|| match c.vendor.as_str() {
                        "0x8086" => "Intel GPU".to_string(),
                        "0x1002" => "AMD GPU".to_string(),
                        "0x10de" => "NVIDIA GPU".to_string(),
                        _ => "GPU".to_string(),
                    });
                GpuCard {
                    path: c.path,
                    dev: c.dev,
                    vendor: c.vendor,
                    pci: c.pci,
                    name,
                    hwmon: c.hwmon,
                    gt_dir: c.gt_dir,
                    xe_freq_dir: c.xe_freq_dir,
                }
            })
            .collect();

        Self {
            cards,
            rc6_prev: HashMap::new(),
            nvidia_smi: find_in_path("nvidia-smi"),
        }
    }

    fn nvidia_is_active(pci: &str) -> bool {
        let status_path = format!("/sys/bus/pci/devices/{}/power/runtime_status", pci);
        read_str(Path::new(&status_path)).as_deref() == Some("active")
    }

    fn query_active_nvidia(&self) -> Vec<GpuEntry> {
        // Strictly check that at least one NVIDIA card is awake BEFORE ever executing nvidia-smi.
        let any_active = self
            .cards
            .iter()
            .any(|c| c.vendor == "0x10de" && Self::nvidia_is_active(&c.pci));
        if !any_active {
            return Vec::new();
        }
        let Some(ref bin) = self.nvidia_smi else {
            return Vec::new();
        };
        let Ok(out) = Command::new(bin)
            .args([
                "--query-gpu=pci.bus_id,name,utilization.gpu,clocks.gr,clocks.max.gr,temperature.gpu,power.draw,memory.used,memory.total",
                "--format=csv,noheader,nounits",
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        else {
            return Vec::new();
        };
        let Ok(text) = std::str::from_utf8(&out.stdout) else {
            return Vec::new();
        };
        let mut res = Vec::new();
        for line in text.lines() {
            let p: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
            if p.len() < 9 {
                continue;
            }
            let num = |s: &str| s.parse::<f64>().ok();
            let pci = p[0]
                .to_ascii_lowercase()
                .replacen("00000000:", "0000:", 1);
            res.push(GpuEntry {
                id: pci,
                busy_estimated: false,
                name: p[1].to_string(),
                vendor: "nvidia".to_string(),
                busy: num(p[2]),
                freq_mhz: num(p[3]),
                max_freq_mhz: num(p[4]),
                temp: num(p[5]),
                temp_shared: false,
                power_w: num(p[6]),
                mem_used: Some(num(p[7]).unwrap_or(0.0) * 1024.0 * 1024.0),
                mem_total: Some(num(p[8]).unwrap_or(0.0) * 1024.0 * 1024.0),
                data_unavailable: None,
            });
        }
        res
    }

    fn intel(&mut self, card: &GpuCard, now: Instant) -> (Option<f64>, Option<f64>, Option<f64>) {
        let mut busy = None;
        let rc6 = card
            .gt_dir
            .as_ref()
            .and_then(|gt| read_u64(&gt.join("rc6_residency_ms")))
            .or_else(|| read_u64(&card.path.join("power/rc6_residency_ms")));
        if let Some(cur_rc6) = rc6 {
            if let Some(&(prev_rc6, prev_t)) = self.rc6_prev.get(&card.path) {
                let dt_ms = now.duration_since(prev_t).as_secs_f64() * 1000.0;
                if dt_ms > 0.0 {
                    let dr = cur_rc6.saturating_sub(prev_rc6) as f64;
                    busy = Some((100.0 - dr * 100.0 / dt_ms).clamp(0.0, 100.0));
                }
            }
            self.rc6_prev.insert(card.path.clone(), (cur_rc6, now));
        }

        let mut act = None;
        let mut mx = None;
        if let Some(ref gt) = card.gt_dir {
            act = read_u64(&gt.join("rps_act_freq_mhz"))
                .filter(|&v| v > 0)
                .or_else(|| read_u64(&gt.join("rps_cur_freq_mhz")));
            mx = read_u64(&gt.join("rps_RP0_freq_mhz"))
                .filter(|&v| v > 0)
                .or_else(|| read_u64(&gt.join("rps_max_freq_mhz")));
        }
        if act.is_none() {
            act = read_u64(&card.path.join("gt_act_freq_mhz"));
            mx = read_u64(&card.path.join("gt_RP0_freq_mhz"))
                .filter(|&v| v > 0)
                .or_else(|| read_u64(&card.path.join("gt_max_freq_mhz")));
        }
        if act.is_none() {
            if let Some(ref xf) = card.xe_freq_dir {
                act = read_u64(&xf.join("act_freq"));
                mx = read_u64(&xf.join("rp0_freq"));
            }
        }
        (busy, act.map(|v| v as f64), mx.map(|v| v as f64))
    }

    fn amd(card: &GpuCard) -> (Option<f64>, Option<f64>, Option<f64>, Option<f64>, Option<f64>) {
        let busy = read_u64(&card.dev.join("gpu_busy_percent")).map(|v| v as f64);
        let used = read_u64(&card.dev.join("mem_info_vram_used")).map(|v| v as f64);
        let total = read_u64(&card.dev.join("mem_info_vram_total")).map(|v| v as f64);
        let mut act: Option<u64> = None;
        let mut mx: Option<u64> = None;
        if let Some(sclk) = read_small(&card.dev.join("pp_dpm_sclk")) {
            for line in sclk.lines() {
                let mut p = line.split_ascii_whitespace();
                let _ = p.next();
                if let Some(tok) = p.next() {
                    let clean = tok.to_ascii_lowercase().replace("mhz", "");
                    if let Ok(mhz) = clean.parse::<u64>() {
                        mx = Some(mx.map_or(mhz, |m| m.max(mhz)));
                        if line.trim_end().ends_with('*') {
                            act = Some(mhz);
                        }
                    }
                }
            }
        }
        if act.is_none() {
            if let Some(ref hw) = card.hwmon {
                act = read_u64(&hw.join("freq1_input"))
                    .filter(|&v| v > 0)
                    .map(|v| v / 1_000_000);
            }
        }
        (busy, act.map(|v| v as f64), mx.map(|v| v as f64), used, total)
    }

    fn snapshot(&mut self, now: Instant, hwmon: &Hwmon, pkg_temp: Option<f64>) -> Vec<GpuEntry> {
        let nvidia = self.query_active_nvidia();
        let nvidia_ids: HashSet<String> = nvidia.iter().map(|g| g.id.clone()).collect();
        let mut out = Vec::with_capacity(self.cards.len() + nvidia.len());

        // Borrow cards via index to allow mutating rc6_prev
        let n = self.cards.len();
        for i in 0..n {
            let vendor = self.cards[i].vendor.clone();
            let pci = self.cards[i].pci.clone();
            if vendor == "0x10de" && nvidia_ids.contains(&pci) {
                continue;
            }
            let name = self.cards[i].name.clone();
            let hw_dir = self.cards[i].hwmon.clone();
            let mut g = GpuEntry {
                id: pci,
                busy_estimated: vendor == "0x8086",
                name,
                vendor: vendor.clone(),
                busy: None,
                freq_mhz: None,
                max_freq_mhz: None,
                temp: None,
                temp_shared: false,
                power_w: None,
                mem_used: None,
                mem_total: None,
                data_unavailable: None,
            };

            if vendor == "0x8086" {
                // Temporarily swap out card info to satisfy borrow checker cleanly
                let card_ref = GpuCard {
                    path: self.cards[i].path.clone(),
                    dev: self.cards[i].dev.clone(),
                    vendor: self.cards[i].vendor.clone(),
                    pci: self.cards[i].pci.clone(),
                    name: String::new(),
                    hwmon: None,
                    gt_dir: self.cards[i].gt_dir.clone(),
                    xe_freq_dir: self.cards[i].xe_freq_dir.clone(),
                };
                let (b, a, m) = self.intel(&card_ref, now);
                g.busy = b;
                g.freq_mhz = a;
                g.max_freq_mhz = m;
                g.vendor = "intel".to_string();
            } else if vendor == "0x1002" {
                let (b, a, m, u, t) = Self::amd(&self.cards[i]);
                g.busy = b;
                g.freq_mhz = a;
                g.max_freq_mhz = m;
                g.mem_used = u;
                g.mem_total = t;
                g.vendor = "amd".to_string();
            } else if vendor == "0x10de" {
                g.vendor = "nvidia".to_string();
                g.data_unavailable = Some(true);
            }

            if let Some(ref hw) = hw_dir {
                g.temp = hwmon.read_hwmon_first_temp(hw);
                g.power_w = hwmon.read_hwmon_power_w(hw);
            }

            if g.temp.is_none()
                && (g.vendor == "intel" || g.vendor == "amd")
                && pkg_temp.is_some()
            {
                g.temp = pkg_temp;
                g.temp_shared = true;
            }
            out.push(g);
        }

        out.extend(nvidia);
        out.sort_by(|a, b| (a.vendor != "nvidia").cmp(&(b.vendor != "nvidia")).then_with(|| a.id.cmp(&b.id)));
        out
    }
}

// ---------------------------------------------------------------- Processes

struct Procs {
    clk_tck: f64,
    page_size: u64,
    prev: HashMap<u32, (u64, u64)>,
    users: HashMap<u32, String>,
    cmdlines: HashMap<u32, (u64, String)>,
}

impl Procs {
    fn new() -> Self {
        let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
        let mut users = HashMap::with_capacity(64);
        if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
            for line in passwd.lines() {
                let mut parts = line.split(':');
                let (Some(name), Some(_), Some(uid_s)) = (parts.next(), parts.next(), parts.next())
                else {
                    continue;
                };
                if let Ok(uid) = uid_s.parse::<u32>() {
                    users.entry(uid).or_insert_with(|| name.to_string());
                }
            }
        }
        Self {
            clk_tck,
            page_size,
            prev: HashMap::with_capacity(512),
            users,
            cmdlines: HashMap::with_capacity(512),
        }
    }

    fn user(&mut self, uid: u32) -> String {
        if let Some(u) = self.users.get(&uid) {
            return u.clone();
        }
        let u = unsafe {
            let pw = libc::getpwuid(uid);
            if !pw.is_null() && !(*pw).pw_name.is_null() {
                CStr::from_ptr((*pw).pw_name)
                    .to_string_lossy()
                    .into_owned()
            } else {
                uid.to_string()
            }
        };
        self.users.insert(uid, u.clone());
        u
    }

    fn cmdline(&mut self, pid: u32, start: u64) -> String {
        if let Some((s, cmd)) = self.cmdlines.get(&pid) {
            if *s == start {
                return cmd.clone();
            }
        }
        let path = format!("/proc/{}/cmdline", pid);
        let cmd = if let Ok(mut f) = File::open(&path) {
            let mut buf = [0u8; 512];
            let n = f.read(&mut buf).unwrap_or(0);
            for b in &mut buf[..n] {
                if *b == 0 {
                    *b = b' ';
                }
            }
            String::from_utf8_lossy(&buf[..n]).trim().to_string()
        } else {
            String::new()
        };
        self.cmdlines.insert(pid, (start, cmd.clone()));
        cmd
    }

    fn snapshot(&mut self, elapsed: f64) -> (Vec<ProcEntry>, u64) {
        let mut procs = Vec::with_capacity(self.prev.len().max(256));
        let mut cur = HashMap::with_capacity(self.prev.len().max(256));
        let mut threads_total = 0u64;
        let mut stat_buf = [0u8; 1024];

        let Ok(rd) = fs::read_dir("/proc") else {
            return (procs, 0);
        };

        for entry in rd.flatten() {
            let fname = entry.file_name();
            let Some(name_s) = fname.to_str() else {
                continue;
            };
            if !name_s.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let Ok(pid) = name_s.parse::<u32>() else {
                continue;
            };
            let stat_path = format!("/proc/{}/stat", pid);
            let Ok(mut f) = File::open(&stat_path) else {
                continue;
            };
            let Ok(uid) = f.metadata().map(|m| m.uid()) else {
                continue;
            };
            let Ok(n) = f.read(&mut stat_buf) else {
                continue;
            };
            let Ok(stat_str) = std::str::from_utf8(&stat_buf[..n]) else {
                continue;
            };
            let (Some(lp), Some(rp)) = (stat_str.find('('), stat_str.rfind(')')) else {
                continue;
            };
            if rp <= lp || rp + 2 > stat_str.len() {
                continue;
            }
            let comm = &stat_str[lp + 1..rp];
            let mut it = stat_str[rp + 2..].split_ascii_whitespace();
            let Some(state_s) = it.next() else { continue };
            let Some(ppid) = it.next().and_then(|s| s.parse::<i32>().ok()) else {
                continue;
            };
            let flags = it.nth(4).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            let Some(utime) = it.nth(4).and_then(|s| s.parse::<u64>().ok()) else {
                continue;
            };
            let Some(stime) = it.next().and_then(|s| s.parse::<u64>().ok()) else {
                continue;
            };
            let Some(nthreads) = it.nth(4).and_then(|s| s.parse::<i64>().ok()) else {
                continue;
            };
            let Some(start) = it.nth(1).and_then(|s| s.parse::<u64>().ok()) else {
                continue;
            };
            let Some(rss_pages) = it.nth(1).and_then(|s| s.parse::<i64>().ok()) else {
                continue;
            };
            let state = state_s.to_string();
            let rss = (rss_pages.max(0) as u64).saturating_mul(self.page_size);
            let ticks = utime.saturating_add(stime);
            cur.insert(pid, (ticks, start));

            let mut cpu = 0.0;
            if let Some(&(pticks, pstart)) = self.prev.get(&pid) {
                if pstart == start && elapsed > 0.0 {
                    cpu = ((ticks.saturating_sub(pticks)) as f64 / self.clk_tck / elapsed * 100.0)
                        .max(0.0);
                }
            }
            threads_total = threads_total.saturating_add(nthreads.max(0) as u64);

            // Kernel threads (PF_KTHREAD = 0x0020_0000) always have empty cmdline.
            let cmd = if (flags & 0x0020_0000) != 0 {
                String::new()
            } else {
                self.cmdline(pid, start)
            };
            let mut proc_name = comm.to_string();
            if comm.len() >= 15 && !cmd.is_empty() {
                let first_tok = cmd.split(' ').next().unwrap_or("");
                let base = Path::new(first_tok)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");
                if base.starts_with(comm) && base.len() <= 40 {
                    proc_name = base.to_string();
                }
            }
            let cmd_trunc: String = cmd.chars().take(200).collect();
            let user = self.user(uid);

            procs.push(ProcEntry {
                pid,
                ppid,
                name: proc_name,
                user,
                cpu: (cpu * 10.0).round() / 10.0,
                mem: rss,
                threads: nthreads,
                state,
                cmd: cmd_trunc,
            });
        }

        self.prev = cur;
        self.cmdlines.retain(|pid, _| self.prev.contains_key(pid));
        (procs, threads_total)
    }
}

fn main() {
    let mut interval = 2.0f64;
    let mut once = false;
    let mut refresh_ec_only = false;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--interval" => {
                if let Some(v) = args.get(i + 1).and_then(|s| s.parse::<f64>().ok()) {
                    interval = v.max(0.5);
                }
                i += 2;
            }
            "--once" => {
                once = true;
                i += 1;
            }
            "--refresh-ec" => {
                refresh_ec_only = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    if refresh_ec_only {
        let hw_full = Hwmon::discover(true);
        let prev = load_slow_cache();
        let _ = refresh_slow_cache_once(&hw_full, &prev.pci_names);
        return;
    }

    let hwmon = Arc::new(Hwmon::discover(false));
    let initial_slow = load_slow_cache();
    let initial_pci = initial_slow.pci_names.clone();
    let slow_cache = Arc::new(Mutex::new(initial_slow));
    let stop_flag = Arc::new(AtomicBool::new(false));

    // In streaming mode, refresh slow Dell EC (dell_smm/dell_ddv), ACPI thermal zones,
    // SMBus/NVMe temps & Wi-Fi SSIDs strictly on a non-blocking background thread every 4 seconds.
    if !once {
        let cache_bg = Arc::clone(&slow_cache);
        let stop_bg = Arc::clone(&stop_flag);
        let pci_bg = initial_pci.clone();
        let _ = std::thread::Builder::new()
            .name("vitalsd-ec".into())
            .spawn(move || {
                let hw_full = Hwmon::discover(true);
                let mut pci_map = pci_bg;
                while !stop_bg.load(Ordering::Relaxed) {
                    let fresh = refresh_slow_cache_once(&hw_full, &pci_map);
                    if pci_map.is_empty() && !fresh.pci_names.is_empty() {
                        pci_map = fresh.pci_names.clone();
                    }
                    if let Ok(mut guard) = cache_bg.lock() {
                        *guard = fresh;
                    }
                    for _ in 0..40 {
                        if stop_bg.load(Ordering::Relaxed) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            });
    }

    let ncpu = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.max(1) as usize;
    let freq_paths: Vec<PathBuf> = (0..ncpu)
        .map(|c| PathBuf::from(format!("/sys/devices/system/cpu/cpu{}/cpufreq/scaling_cur_freq", c)))
        .collect();
    let core_ids: Vec<Option<u32>> = (0..ncpu)
        .map(|c| {
            read_u64(Path::new(&format!(
                "/sys/devices/system/cpu/cpu{}/topology/core_id",
                c
            )))
            .map(|v| v as u32)
        })
        .collect();

    let model = cpu_model();
    let host = get_hostname();
    let mut rapl = Rapl::new();
    let mut gpus = Gpus::discover(&initial_pci);
    let mut procs = Procs::new();

    let mut prev_cpu = cpu_times();
    let mut prev_disk = diskstats();
    let mut prev_net = net_dev();
    let mut prev_t = Instant::now();
    // Seed RAPL baseline without blocking
    let _ = rapl.watts(prev_t);

    let slow_every = 5usize;
    let mut frame = 0usize;
    let mut ips: HashMap<String, String> = HashMap::new();
    let mut mount_list: Vec<MountInfo> = Vec::new();

    let stdout = io::stdout();
    let mut out = BufWriter::with_capacity(65536, stdout.lock());

    loop {
        let now = Instant::now();
        let elapsed = if frame == 0 {
            0.0
        } else {
            now.duration_since(prev_t).as_secs_f64().max(1e-3)
        };

        let cur_cpu = if frame == 0 {
            prev_cpu.clone()
        } else {
            cpu_times()
        };
        let pct = cpu_percentages(&prev_cpu, &cur_cpu);
        let cores: Vec<f64> = (0..ncpu)
            .map(|c| *pct.get(&format!("cpu{}", c)).unwrap_or(&0.0))
            .collect();

        let (pkg_temp, core_temps) = hwmon.read_coretemp(&core_ids);
        let freqs = cpu_freqs(&freq_paths);
        let (f_sum, f_cnt) = freqs.iter().flatten().fold((0u64, 0usize), |(s, c), &v| (s + v, c + 1));
        let freq_mhz = if f_cnt > 0 {
            Some(f_sum as f64 / f_cnt as f64)
        } else {
            None
        };

        let load_raw = fs::read_to_string("/proc/loadavg").unwrap_or_else(|_| "0 0 0 0/0 0".to_string());
        let load_parts: Vec<&str> = load_raw.split_ascii_whitespace().collect();
        let load = [
            load_parts.first().and_then(|s| s.parse().ok()).unwrap_or(0.0),
            load_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.0),
            load_parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0),
        ];
        let running = load_parts
            .get(3)
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);

        let uptime = fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| s.split_ascii_whitespace().next().and_then(|v| v.parse().ok()))
            .unwrap_or(0.0);

        let slow_snap = slow_cache.lock().map(|g| g.clone()).unwrap_or_default();

        // Disks
        let cur_disk = if frame == 0 {
            prev_disk.clone()
        } else {
            diskstats()
        };
        if frame % slow_every == 0 {
            mount_list = read_mounts();
        }
        let mut disks = Vec::with_capacity(mount_list.len());
        for m in &mount_list {
            let (mut r, mut w) = (None, None);
            if elapsed > 0.0 {
                if let Some(ref dev) = m.dev {
                    if let (Some(&(cr, cw)), Some(&(pr, pw))) =
                        (cur_disk.get(dev), prev_disk.get(dev))
                    {
                        r = Some(cr.saturating_sub(pr) as f64 / elapsed);
                        w = Some(cw.saturating_sub(pw) as f64 / elapsed);
                    }
                }
            }
            let temp = m
                .dev
                .as_deref()
                .and_then(|d| slow_snap.drive_temps.get(d).copied());
            disks.push(DiskEntry {
                mount: m.mount.clone(),
                source: m.source.clone(),
                fstype: m.fstype.clone(),
                total: m.total,
                used: m.used,
                free: m.free,
                mounts: m.mounts.clone(),
                read_bps: r,
                write_bps: w,
                temp,
            });
        }

        // Network
        let cur_net = if frame == 0 {
            prev_net.clone()
        } else {
            net_dev()
        };
        if frame % slow_every == 0 {
            ips = iface_ips();
        }
        let dflt = default_iface();
        let mut ifaces = Vec::with_capacity(cur_net.len());
        for (name, &(rx, tx)) in &cur_net {
            if name == "lo" {
                continue;
            }
            let oper = read_str(Path::new(&format!("/sys/class/net/{}/operstate", name)))
                .unwrap_or_else(|| "unknown".to_string());
            let (prx, ptx) = prev_net.get(name).copied().unwrap_or((rx, tx));
            let (rx_bps, tx_bps) = if elapsed > 0.0 {
                (
                    rx.saturating_sub(prx) as f64 / elapsed,
                    tx.saturating_sub(ptx) as f64 / elapsed,
                )
            } else {
                (0.0, 0.0)
            };
            ifaces.push(NetIface {
                name: name.clone(),
                up: oper == "up" || (oper == "unknown" && rx > 0),
                ip: ips.get(name).cloned(),
                wireless: Path::new(&format!("/sys/class/net/{}/wireless", name)).is_dir(),
                ssid: slow_snap.ssids.get(name).cloned(),
                rx_bps,
                tx_bps,
                rx_total: rx,
                tx_total: tx,
            });
        }
        ifaces.sort_by(|a, b| {
            let ad = dflt.as_deref() != Some(a.name.as_str());
            let bd = dflt.as_deref() != Some(b.name.as_str());
            ad.cmp(&bd)
                .then_with(|| (!a.up).cmp(&(!b.up)))
                .then_with(|| a.name.cmp(&b.name))
        });

        let (plist, threads_total) = procs.snapshot(elapsed);
        let (sensor_temps, sensor_fans, cpu_fans) = hwmon.read_fast_sensors(&slow_snap);
        let power_w = if frame == 0 { None } else { rapl.watts(now) };
        let gpu_list = gpus.snapshot(now, &hwmon, pkg_temp);

        let snap = Snapshot {
            t: now_epoch(),
            host: host.clone(),
            uptime,
            load,
            ncpu,
            procs: ProcsSummary {
                total: plist.len(),
                running,
                threads: threads_total,
            },
            cpu: CpuSection {
                model: model.clone(),
                total: *pct.get("cpu").unwrap_or(&0.0),
                cores,
                freq_mhz,
                core_freq: freqs,
                temp: pkg_temp,
                core_temps,
                fans: cpu_fans,
                power_w,
            },
            mem: read_meminfo(),
            disks,
            nvme_temp: slow_snap.nvme_temp,
            sensors: SensorsSection {
                temps: sensor_temps,
                fans: sensor_fans,
            },
            net: NetSection {
                default: dflt,
                ifaces,
            },
            gpus: gpu_list,
            processes: plist,
        };

        if serde_json::to_writer(&mut out, &snap).is_err()
            || out.write_all(b"\n").is_err()
            || out.flush().is_err()
        {
            break;
        }

        if once {
            break;
        }

        prev_cpu = cur_cpu;
        prev_disk = cur_disk;
        prev_net = cur_net;
        prev_t = now;
        // Fast second sample (250ms) after instant frame 0 so live CPU%, net bps,
        // RAPL watts, and Intel RC6 busy% populate almost immediately without
        // blocking initial popup paint!
        let sleep_secs = if frame == 0 {
            interval.min(0.25)
        } else {
            interval
        };
        frame += 1;
        std::thread::sleep(Duration::from_secs_f64(sleep_secs));
    }

    stop_flag.store(true, Ordering::Relaxed);
}
