pub(super) use super::super::worker_process::require_containment;
use super::*;
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io,
    os::windows::{ffi::OsStringExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::PathBuf,
    time::Duration,
};
#[cfg(test)]
use std::{thread, time::Instant};
use windows_sys::Win32::Storage::FileSystem::{
    GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, FILE_SHARE_READ, VOLUME_NAME_DOS,
};
const DEADLINE: Duration = Duration::from_secs(10);
pub(super) fn pin_file(path: &Path) -> io::Result<(PathBuf, File)> {
    pin_bounded_file(path, MAX_FILE_BYTES)
}

fn pin_bounded_file(path: &Path, max_bytes: u64) -> io::Result<(PathBuf, File)> {
    // Restrict the diagnostic to local disk paths: no UNC, named pipe, device,
    // alternate data stream or verbatim path supplied by the caller.
    let absolute = std::path::absolute(path)?;
    let text = absolute.as_os_str().to_string_lossy();
    let bytes = text.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || !matches!(bytes[2], b'\\' | b'/')
        || text[2..].contains(':')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ETL requires a local disk file",
        ));
    }
    // Windows denies existing/future write and delete opens while this handle
    // lives. Pin before resolving the path passed to the native file reader.
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&absolute)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ETL input file is empty, not regular, or exceeds its size limit",
        ));
    }
    // Resolve using the opened handle, not a second lookup of the supplied path.
    // Keep UTF-16 intact and reject resolved UNC/device/stream paths as well.
    let mut resolved = vec![0u16; 32768];
    let count = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            resolved.as_mut_ptr(),
            resolved.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    } as usize;
    if count == 0 {
        return Err(io::Error::last_os_error());
    }
    if count >= resolved.len() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    resolved.truncate(count);
    let prefix: Vec<u16> = r"\\?\".encode_utf16().collect();
    let tail = resolved
        .strip_prefix(prefix.as_slice())
        .ok_or(io::ErrorKind::InvalidInput)?;
    if tail.len() < 3
        || !matches!(tail[0], 65..=90 | 97..=122)
        || tail[1] != b':' as u16
        || tail[2] != b'\\' as u16
        || tail[2..].contains(&(b':' as u16))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ETL requires a resolved local disk file",
        ));
    }
    Ok((PathBuf::from(OsString::from_wide(tail)), file))
}

pub(super) fn inspect(path: &Path) -> io::Result<EtlReport> {
    let (path, pin) = pin_file(path)?;
    inspect_pinned(path, &pin)
}

pub(super) fn inspect_with_closure(path: &Path, receipt: &Path) -> io::Result<ClosureInspection> {
    let (_, receipt_pin) = pin_bounded_file(receipt, closure::MAX_RECEIPT_BYTES)?;
    let receipt = closure::read(receipt_pin)?;
    let (path, mut pin) = pin_file(path)?;
    let size = pin.metadata()?.len();
    let sha256 = closure::fingerprint(&mut pin, size)?;
    let report = inspect_pinned(path, &pin)?;
    Ok(closure::check(receipt, sha256, report))
}

fn inspect_pinned(path: PathBuf, pin: &File) -> io::Result<EtlReport> {
    let executable = std::env::current_exe()?;
    let args = [OsString::from("--etl-worker"), path.into_os_string()];
    let bytes = supervise(
        &executable,
        &args,
        executable.parent().ok_or(io::ErrorKind::InvalidInput)?,
        DEADLINE,
    )?;
    assemble(&bytes, pin.metadata()?.len())
}

fn supervise(
    executable: &Path,
    args: &[OsString],
    cwd: &Path,
    deadline: Duration,
) -> io::Result<Vec<u8>> {
    super::super::worker_process::run(executable, args, cwd, deadline, MAX_REPORT_BYTES)
        .map(|result| result.bytes)
        .map_err(|failure| failure.error)
}

#[cfg(test)]
mod tests;
