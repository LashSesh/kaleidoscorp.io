use super::super::{
    etl::closure,
    session::{Properties, Snapshot, PRIVATE_MODE},
};
use super::controller::{self, Backend};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    ptr,
    time::Instant,
};
use windows_sys::{
    core::GUID,
    Win32::{
        Storage::FileSystem::{FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_READ},
        System::Diagnostics::Etw::*,
    },
};

const NAME: &str = "ScorpioSync.PrivateCaptureAcceptance";
const FILE_MIB: u64 = 1;

struct PrivateBackend {
    guid: GUID,
    guid_text: String,
    registration: u64,
    file: Vec<u16>,
}

impl Drop for PrivateBackend {
    fn drop(&mut self) {
        unsafe {
            EventUnregister(self.registration as REGHANDLE);
        }
    }
}

fn guid_text(g: GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7]
    )
}

impl PrivateBackend {
    fn new(path: &Path) -> io::Result<Self> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| io::Error::other("session GUID generation failed"))?;
        random[6] = (random[6] & 0x0f) | 0x40;
        random[8] = (random[8] & 0x3f) | 0x80;
        let guid = GUID::from_u128(u128::from_be_bytes(random));
        let file: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        if file.len() > 1024 || file[..file.len() - 1].contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut registration = 0;
        let status = unsafe { EventRegister(&guid, None, ptr::null(), &mut registration) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(Self {
            guid,
            guid_text: guid_text(guid),
            registration,
            file,
        })
    }

    fn properties(&self, start: bool) -> Vec<u64> {
        // A full buffer for native output too; fresh zeroed QUERY/STOP storage.
        let bytes = size_of::<EVENT_TRACE_PROPERTIES>() + 4 * 1024;
        let mut storage = vec![0u64; bytes.div_ceil(8)];
        let raw = storage.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
        unsafe {
            (*raw).Wnode.BufferSize = (storage.len() * 8) as u32;
            (*raw).Wnode.Guid = self.guid;
            (*raw).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*raw).LogFileMode = PRIVATE_MODE;
            (*raw).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            (*raw).LogFileNameOffset = (size_of::<EVENT_TRACE_PROPERTIES>() + 2 * 1024) as u32;
            if start {
                (*raw).Wnode.ClientContext = 1;
                (*raw).BufferSize = 64;
                (*raw).MinimumBuffers = 2;
                (*raw).MaximumBuffers = 2;
                (*raw).MaximumFileSize = FILE_MIB as u32;
                (*raw).FlushTimer = 1;
                ptr::copy_nonoverlapping(
                    self.file.as_ptr(),
                    raw.cast::<u8>()
                        .add((*raw).LogFileNameOffset as usize)
                        .cast(),
                    self.file.len(),
                );
            }
        }
        storage
    }

    fn control(&self, handle: &CONTROLTRACE_HANDLE, operation: u32) -> Snapshot {
        let mut storage = self.properties(false);
        let raw = storage.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
        let api_status = unsafe { ControlTraceW(*handle, ptr::null(), raw, operation) };
        let properties = if api_status == 0 {
            let p = unsafe { &*raw };
            Some(Properties {
                session_guid: guid_text(p.Wnode.Guid),
                log_file_mode: p.LogFileMode,
                enable_flags: p.EnableFlags,
                events_lost: p.EventsLost,
                log_buffers_lost: p.LogBuffersLost,
                realtime_buffers_lost: p.RealTimeBuffersLost,
                buffers_written: p.BuffersWritten,
            })
        } else {
            None
        };
        Snapshot {
            api_status,
            properties,
        }
    }
}

impl Backend for PrivateBackend {
    type Handle = CONTROLTRACE_HANDLE;
    fn start(&mut self) -> Result<Self::Handle, u32> {
        let name: Vec<u16> = NAME.encode_utf16().chain(Some(0)).collect();
        let mut storage = self.properties(true);
        let mut handle = unsafe { zeroed() };
        let status =
            unsafe { StartTraceW(&mut handle, name.as_ptr(), storage.as_mut_ptr().cast()) };
        if status != 0 {
            return Err(status);
        }
        // Return ownership immediately. Provider enabling happens under the
        // controller's Drop guard, so an enable failure still stops our session.
        Ok(handle)
    }
    fn query(&mut self, handle: &Self::Handle) -> Snapshot {
        self.control(handle, EVENT_TRACE_CONTROL_QUERY)
    }
    fn enable(&mut self, handle: &Self::Handle) -> Result<(), u32> {
        let status = unsafe {
            EnableTraceEx2(
                *handle,
                &self.guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                5,
                1,
                0,
                0,
                ptr::null(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(status)
        }
    }
    fn emit(&mut self, ordinal: u32) -> Result<(), u32> {
        let descriptor = EVENT_DESCRIPTOR {
            Id: 1,
            Version: 1,
            Level: 4,
            Keyword: 1,
            ..unsafe { zeroed() }
        };
        let _ = ordinal;
        let status =
            unsafe { EventWrite(self.registration as REGHANDLE, &descriptor, 0, ptr::null()) };
        if status == 0 {
            Ok(())
        } else {
            Err(status)
        }
    }
    fn stop(&mut self, handle: &Self::Handle) -> Snapshot {
        self.control(handle, EVENT_TRACE_CONTROL_STOP)
    }
}

fn checked_directory(path: &Path, existing: bool) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let text = absolute.to_string_lossy();
    let bytes = text.as_bytes();
    if bytes.len() < 4
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || !matches!(bytes[2], b'\\' | b'/')
        || text[2..].contains(':')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "capture requires a new local directory",
        ));
    }
    let parent = absolute.parent().ok_or(io::ErrorKind::InvalidInput)?;
    // Refuse existing reparses in the path; do not follow or repair them.
    for ancestor in if existing { absolute.as_path() } else { parent }.ancestors() {
        let m = fs::symlink_metadata(ancestor)?;
        if !m.is_dir() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
    }
    Ok(absolute)
}

pub(super) fn output_directory(path: &Path) -> io::Result<PathBuf> {
    let absolute = checked_directory(path, false)?;
    fs::create_dir(&absolute)?;
    Ok(absolute)
}

pub(super) fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

pub(super) fn fixture_prepared(directory: &Path) -> io::Result<u32> {
    let directory = checked_directory(directory, true)?;
    if fs::read_dir(&directory)?.next().is_some() {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    let path = directory.join("recording.etl");
    let backend = PrivateBackend::new(&path)?;
    let guid = backend.guid_text.clone();
    let started = Instant::now();
    let report = controller::run(backend, &guid, || {
        started.elapsed().as_millis().min(u64::MAX as u128) as u64
    })
    .map_err(|code| io::Error::from_raw_os_error(code as i32))?;
    write_new(
        &directory.join("controller.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    if report.failure.is_some() {
        return Err(io::Error::other(
            "private capture failed; inspect controller.json",
        ));
    }
    let mut file: File = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&path)?;
    let size = file.metadata()?.len();
    if size == 0 || size > FILE_MIB * 1024 * 1024 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let hash = closure::fingerprint(&mut file, size)?;
    let receipt = closure::private_receipt(
        size,
        hash,
        guid,
        report.query_after_start,
        report.stop.ok_or(io::ErrorKind::InvalidData)?,
    )?;
    write_new(&directory.join("closure.json"), &receipt)?;
    Ok(report.events_submitted)
}

pub(super) fn check_artifact_sizes(directory: &Path) -> io::Result<()> {
    for (name, limit) in [
        ("recording.etl", FILE_MIB * 1024 * 1024),
        ("controller.json", 16384),
        ("closure.json", 16384),
    ] {
        let meta = fs::symlink_metadata(directory.join(name))?;
        if !meta.is_file()
            || meta.len() == 0
            || meta.len() > limit
            || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    Ok(())
}

/// Fault injection exists only in the library test executable, never in CLI
/// arguments, environment variables or production provider configuration.
#[cfg(test)]
pub(super) fn fault_capture(directory: &Path, kind: &str) -> io::Result<()> {
    struct FaultBackend<'a> {
        inner: PrivateBackend,
        directory: &'a Path,
        kind: &'a str,
    }
    impl Backend for FaultBackend<'_> {
        type Handle = CONTROLTRACE_HANDLE;
        fn start(&mut self) -> Result<Self::Handle, u32> {
            self.inner.start()
        }
        fn enable(&mut self, h: &Self::Handle) -> Result<(), u32> {
            self.inner.enable(h)
        }
        fn query(&mut self, h: &Self::Handle) -> Snapshot {
            self.inner.query(h)
        }
        fn stop(&mut self, h: &Self::Handle) -> Snapshot {
            self.inner.stop(h)
        }
        fn emit(&mut self, n: u32) -> Result<(), u32> {
            if n == 0 {
                fs::write(
                    self.directory.join("worker-ready"),
                    std::process::id().to_string(),
                )
                .unwrap();
                match self.kind {
                    "crash" => std::process::exit(23),
                    "hang" => std::thread::sleep(std::time::Duration::from_secs(30)),
                    "overflow" => loop {
                        std::io::stdout().write_all(&[b'x'; 4096]).unwrap();
                    },
                    "malformed" => {
                        std::io::stdout().write_all(b"not-a-completion").unwrap();
                    }
                    _ => panic!("unknown test fault"),
                }
            }
            self.inner.emit(n)
        }
    }
    let inner = PrivateBackend::new(&directory.join("recording.etl"))?;
    let guid = inner.guid_text.clone();
    let clock = Instant::now();
    let _ = controller::run(
        FaultBackend {
            inner,
            directory,
            kind,
        },
        &guid,
        || clock.elapsed().as_millis() as u64,
    )
    .map_err(|c| io::Error::from_raw_os_error(c as i32))?;
    Ok(())
}
