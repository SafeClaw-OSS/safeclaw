//! Reading a GitHub source tarball in memory.
//!
//! The archive (`tar.gz`, one top-level folder `<owner>-<repo>-<sha>/`) is
//! streamed through gzip with caps on the compressed bytes, the unpacked
//! bytes and the entry count; nothing is written to disk. Only regular files
//! at the four fixed paths of a source ([`super::fixed_path`]) are read, each
//! within the definition size limit. Symlinks, hard links and devices are
//! never read (one at a fixed path is reported); an absolute path or a `..`
//! component anywhere rejects the archive (PEP 706's data filter, plus the
//! size and count bounds it says it does not provide).
//!
//! The format handled is what `git archive` writes: POSIX ustar headers, pax
//! extended headers (`path`, `size`) and the pax global header, plus GNU
//! long names for robustness. Everything else about an entry is ignored.

use std::io::Read;

use super::{
    fixed_path, FileKind, Layout, SourceFiles, MAX_TARBALL_BYTES, MAX_TARBALL_ENTRIES,
    MAX_TARBALL_UNPACKED_BYTES,
};
use crate::service::limits::MAX_FILE_BYTES;

const BLOCK: usize = 512;
/// A pax extended header or a GNU long name: metadata, not content.
const MAX_META_BYTES: u64 = 64 * 1024;

/// A reader that fails once more than `left` bytes come out of `inner`, so a
/// small archive that unpacks to a huge one is refused instead of read.
struct Capped<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(std::io::Error::other("unpacked size limit")),
            };
        }
        let want = buf.len().min(self.left.min(usize::MAX as u64) as usize);
        let n = self.inner.read(&mut buf[..want])?;
        self.left -= n as u64;
        Ok(n)
    }
}

fn io_err(e: std::io::Error) -> String {
    if e.to_string().contains("unpacked size limit") {
        format!(
            "the archive unpacks to more than {} bytes",
            MAX_TARBALL_UNPACKED_BYTES
        )
    } else {
        "the archive is truncated or not a gzip tarball".to_string()
    }
}

/// Read the source at `sub` (a sub-folder, or the repository root) out of a
/// `tar.gz`. See the module docs for what is read and what is refused.
pub fn read_tarball(gz: &[u8], sub: Option<&str>) -> Result<SourceFiles, Vec<String>> {
    read_tarball_with(gz, sub, MAX_TARBALL_UNPACKED_BYTES, MAX_TARBALL_ENTRIES)
}

pub(crate) fn read_tarball_with(
    gz: &[u8],
    sub: Option<&str>,
    unpacked_cap: u64,
    entry_cap: usize,
) -> Result<SourceFiles, Vec<String>> {
    if gz.len() > MAX_TARBALL_BYTES {
        return Err(vec![format!(
            "the archive is {} bytes; the limit is {}",
            gz.len(),
            MAX_TARBALL_BYTES
        )]);
    }
    let mut rd = Capped {
        inner: flate2::read::GzDecoder::new(gz),
        left: unpacked_cap,
    };
    let mut lay = Layout::default();
    let mut seen_under_sub = false;
    let mut read_paths: std::collections::BTreeSet<String> = Default::default();
    let mut pending_path: Option<Vec<u8>> = None;
    let mut pending_size: Option<u64> = None;
    let mut entries = 0usize;
    let mut header = [0u8; BLOCK];
    loop {
        read_full(&mut rd, &mut header).map_err(|e| vec![e])?;
        if header.iter().all(|b| *b == 0) {
            break; // end-of-archive marker
        }
        entries += 1;
        if entries > entry_cap {
            return Err(vec![format!(
                "the archive has more than {} entries",
                entry_cap
            )]);
        }
        if !checksum_ok(&header) {
            return Err(vec!["the archive has a corrupt entry header".into()]);
        }
        let kind = header[156];
        let size = match pending_size.take() {
            Some(s) => s,
            None => parse_octal(&header[124..136]).ok_or_else(|| {
                vec!["the archive has an entry with an unreadable size".to_string()]
            })?,
        };
        match kind {
            // pax extended header: applies to the next entry.
            b'x' => {
                let data = read_meta(&mut rd, size).map_err(|e| vec![e])?;
                let (p, s) = parse_pax(&data).map_err(|e| vec![e])?;
                if p.is_some() {
                    pending_path = p;
                }
                pending_size = s;
                continue;
            }
            // pax global header (git archive's commit comment): nothing we use.
            b'g' => {
                read_meta(&mut rd, size).map_err(|e| vec![e])?;
                continue;
            }
            // GNU long name / long link name.
            b'L' => {
                let mut data = read_meta(&mut rd, size).map_err(|e| vec![e])?;
                while data.last() == Some(&0) {
                    data.pop();
                }
                pending_path = Some(data);
                continue;
            }
            b'K' => {
                read_meta(&mut rd, size).map_err(|e| vec![e])?;
                continue;
            }
            _ => {}
        }
        let path = pending_path.take().unwrap_or_else(|| ustar_path(&header));
        check_path(&path).map_err(|e| vec![e])?;
        let rel = std::str::from_utf8(&path)
            .ok()
            .and_then(|p| strip_root(p, sub));
        let regular = kind == b'0' || kind == 0;
        // Links, devices and FIFOs carry no data to skip (a hard link's size
        // field is ignored by tar); a directory carries none either.
        let has_data = regular || !matches!(kind, b'1' | b'2' | b'3' | b'4' | b'5' | b'6');
        let Some(rel) = rel else {
            if has_data {
                skip(&mut rd, size).map_err(|e| vec![e])?;
            }
            continue;
        };
        seen_under_sub = true;
        note_layout(&rel, kind == b'5', &mut lay);
        let Some((key, file_kind)) = fixed_path(rel.trim_end_matches('/')) else {
            if has_data {
                skip(&mut rd, size).map_err(|e| vec![e])?;
            }
            continue;
        };
        let label = shown_path(&key, file_kind);
        if !regular {
            let what = match kind {
                b'2' => "is a symbolic link",
                b'1' => "is a hard link",
                b'5' => "is a folder",
                _ => "is a device or special file",
            };
            lay.problems
                .push(format!("{} {}; only regular files are read", label, what));
            if has_data {
                skip(&mut rd, size).map_err(|e| vec![e])?;
            }
            continue;
        }
        if !read_paths.insert(rel.trim_end_matches('/').to_string()) {
            return Err(vec![format!("{} appears twice in the archive", label)]);
        }
        if size > MAX_FILE_BYTES as u64 {
            lay.problems.push(format!(
                "{} is {} bytes; the limit is {}",
                label, size, MAX_FILE_BYTES
            ));
            skip(&mut rd, size).map_err(|e| vec![e])?;
            continue;
        }
        let mut data = vec![0u8; size as usize];
        read_full(&mut rd, &mut data).map_err(|e| vec![e])?;
        skip_padding(&mut rd, size).map_err(|e| vec![e])?;
        if file_kind == FileKind::Icon {
            if key.is_empty() {
                lay.root_icon = Some(data);
            } else {
                lay.folders.entry(key).or_default().icon = Some(data);
            }
            continue;
        }
        let Ok(text) = String::from_utf8(data) else {
            lay.problems.push(format!("{} is not UTF-8", label));
            continue;
        };
        if key.is_empty() {
            match file_kind {
                FileKind::Policy => lay.root_policy = Some(text),
                _ => lay.root_service = Some(text),
            }
        } else {
            let slot = lay.folders.entry(key).or_default();
            match file_kind {
                FileKind::Policy => slot.policy = Some(text),
                _ => slot.service = Some(text),
            }
        }
    }
    if let Some(p) = sub {
        if !seen_under_sub {
            return Err(vec![format!(
                "{} is not a folder in this repository",
                crate::util::terminal_safe(p)
            )]);
        }
    }
    lay.finish()
}

/// Record what an entry under the source root says about the layout: a
/// folder under `services/` (its own entry, or any entry inside it) is a
/// service slot; a plain file directly in `services/` (a README) is not.
fn note_layout(rel: &str, is_dir: bool, lay: &mut Layout) {
    let rel = rel.trim_end_matches('/');
    if rel == "service.toml" {
        lay.root_service_seen = true;
    }
    if rel == "services" || rel.starts_with("services/") {
        lay.services_seen = true;
        if let Some(rest) = rel.strip_prefix("services/") {
            let key = rest.split('/').next().unwrap_or("");
            if !key.is_empty() && (rest.contains('/') || is_dir) {
                lay.folders.entry(key.to_string()).or_default();
            }
        }
    }
}

/// A fixed path as shown in a problem (the folder name is untrusted).
fn shown_path(key: &str, kind: FileKind) -> String {
    let file = kind.file_name();
    if key.is_empty() {
        file.to_string()
    } else {
        format!("services/{}/{}", crate::util::terminal_safe(key), file)
    }
}

/// The path relative to the source root: drop the archive's top-level folder,
/// then the `sub` folder. `None` when the entry is outside the source.
fn strip_root(path: &str, sub: Option<&str>) -> Option<String> {
    let (_, rest) = path.split_once('/')?;
    match sub {
        None => Some(rest.to_string()),
        Some(s) => {
            let inner = rest.strip_prefix(s)?;
            if inner.is_empty() {
                return None; // the sub folder entry itself
            }
            inner.strip_prefix('/').map(str::to_string)
        }
    }
}

/// Refuse an absolute path or a `..` component anywhere in the archive.
fn check_path(path: &[u8]) -> Result<(), String> {
    if path.first() == Some(&b'/') {
        return Err("the archive has an entry with an absolute path".into());
    }
    if path.split(|b| *b == b'/').any(|c| c == b"..") {
        return Err("the archive has an entry that leaves its folder ('..')".into());
    }
    Ok(())
}

fn ustar_path(h: &[u8; BLOCK]) -> Vec<u8> {
    let field = |b: &[u8]| -> Vec<u8> {
        let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
        b[..end].to_vec()
    };
    let name = field(&h[0..100]);
    let ustar = &h[257..262] == b"ustar";
    let prefix = if ustar {
        field(&h[345..500])
    } else {
        Vec::new()
    };
    if prefix.is_empty() {
        name
    } else {
        let mut p = prefix;
        p.push(b'/');
        p.extend_from_slice(&name);
        p
    }
}

fn checksum_ok(h: &[u8; BLOCK]) -> bool {
    let Some(want) = parse_octal(&h[148..156]) else {
        return false;
    };
    let mut unsigned: u64 = 0;
    let mut signed: i64 = 0;
    for (i, b) in h.iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { *b };
        unsigned += b as u64;
        signed += (b as i8) as i64;
    }
    unsigned == want || signed == want as i64
}

/// An octal numeric field (NUL/space padded). Base-256 sizes (> 8 GiB) are
/// refused: nothing that large is ever read.
fn parse_octal(f: &[u8]) -> Option<u64> {
    if f.first().is_some_and(|b| b & 0x80 != 0) {
        return None;
    }
    let s: Vec<u8> = f
        .iter()
        .copied()
        .skip_while(|b| *b == b' ')
        .take_while(|b| *b != 0 && *b != b' ')
        .collect();
    if s.is_empty() {
        return Some(0);
    }
    let mut v: u64 = 0;
    for b in s {
        if !(b'0'..=b'7').contains(&b) {
            return None;
        }
        v = v.checked_mul(8)?.checked_add((b - b'0') as u64)?;
    }
    Some(v)
}

/// The `path` and `size` records of a pax extended header (`"<len> k=v\n"`).
fn parse_pax(data: &[u8]) -> Result<(Option<Vec<u8>>, Option<u64>), String> {
    const BAD: &str = "the archive has a malformed extended header";
    let mut path = None;
    let mut size = None;
    let mut rest = data;
    while !rest.is_empty() {
        if rest.iter().all(|b| *b == 0) {
            break;
        }
        let sp = rest.iter().position(|b| *b == b' ').ok_or(BAD)?;
        let len: usize = std::str::from_utf8(&rest[..sp])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(BAD)?;
        if len <= sp + 1 || len > rest.len() || rest[len - 1] != b'\n' {
            return Err(BAD.into());
        }
        let rec = &rest[sp + 1..len - 1];
        let eq = rec.iter().position(|b| *b == b'=').ok_or(BAD)?;
        let (k, v) = (&rec[..eq], &rec[eq + 1..]);
        match k {
            b"path" => path = Some(v.to_vec()),
            b"size" => {
                size = Some(
                    std::str::from_utf8(v)
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .ok_or(BAD)?,
                )
            }
            _ => {}
        }
        rest = &rest[len..];
    }
    Ok((path, size))
}

fn read_full<R: Read>(rd: &mut R, buf: &mut [u8]) -> Result<(), String> {
    rd.read_exact(buf).map_err(io_err)
}

fn padded(size: u64) -> u64 {
    size.div_ceil(BLOCK as u64) * BLOCK as u64
}

fn read_meta<R: Read>(rd: &mut R, size: u64) -> Result<Vec<u8>, String> {
    if size > MAX_META_BYTES {
        return Err("the archive has an oversized extended header".into());
    }
    let mut data = vec![0u8; size as usize];
    read_full(rd, &mut data)?;
    skip_padding(rd, size)?;
    Ok(data)
}

fn skip_padding<R: Read>(rd: &mut R, size: u64) -> Result<(), String> {
    discard(rd, padded(size) - size)
}

fn skip<R: Read>(rd: &mut R, size: u64) -> Result<(), String> {
    discard(rd, padded(size))
}

fn discard<R: Read>(rd: &mut R, n: u64) -> Result<(), String> {
    let copied = std::io::copy(&mut rd.by_ref().take(n), &mut std::io::sink()).map_err(io_err)?;
    if copied != n {
        return Err("the archive is truncated".into());
    }
    Ok(())
}
