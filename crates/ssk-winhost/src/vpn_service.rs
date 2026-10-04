//! Protected VPN broker composition. No provisioning, tunnel release or routes.
use crate::{
    vpn_launch::{LaunchFailure, PreparedVpn},
    vpn_profiles::ProfileStore,
};
use ssk_netd_helper::{vpn, CapabilityToken};
use std::{collections::BTreeSet, io, sync::atomic::AtomicBool};

pub struct Configuration {
    policy: vpn::Policy,
    journal: vpn::journal::Journal,
    snapshot: WindowsBackend,
}
impl Configuration {
    /// Missing/unsafe policy disables this domain; never auto-grants an admin.
    pub fn open() -> Result<Self, String> {
        let profiles = ProfileStore::open().map_err(|e| e.to_string())?;
        let store = crate::vpn_journal::SegmentedJournal::open(
            ProfileStore::open().map_err(|e| e.to_string())?,
            true,
        )
        .map_err(|e| e.to_string())?;
        let journal = vpn::journal::Journal::open(Box::new(store)).map_err(|e| e.to_string())?;
        let snapshot = crate::vpn_configuration::load_for_service(
            &profiles,
            &journal,
            &crate::service::Win32PathSecurityProbe,
        )
        .map_err(|e| e.to_string())?;
        Ok(Self {
            policy: snapshot.policy,
            journal,
            snapshot: WindowsBackend {
                profiles: snapshot.profiles,
                _document: snapshot.document,
            },
        })
    }
    pub fn client_sids(&self) -> BTreeSet<String> {
        self.policy.client_sids()
    }
    pub fn start(self, token: CapabilityToken) -> io::Result<vpn::Service> {
        vpn::Service::start_with_journal(self.policy, token, self.journal, self.snapshot)
    }
}

#[cfg(test)]
pub(crate) use crate::vpn_journal::FileJournal;

struct WindowsBackend {
    profiles: vpn::configuration::ProfileSet,
    _document: Option<crate::vpn_configuration::SecretDocument>,
}
impl vpn::Backend for WindowsBackend {
    fn prepare(
        &mut self,
        profile: &ssk_vpnctl::ProfileId,
        cancelled: &AtomicBool,
        on_created: &mut dyn FnMut(vpn::ProcessIdentity) -> bool,
    ) -> Result<Box<dyn vpn::LiveSession>, vpn::PrepareError> {
        let profile = self.profiles.get(profile).ok_or(vpn::PrepareError {
            exit_confirmed: None,
            cancelled: false,
        })?;
        PreparedVpn::prepare_tracked(profile, cancelled, on_created)
            .map(|p| Box::new(p) as Box<dyn vpn::LiveSession>)
            .map_err(|error| {
                tracing::warn!(target: "ssk.vpn", reason = ?error.reason,
                    exit_confirmed = ?error.process_exit_confirmed, "VPN preparation did not complete");
                vpn::PrepareError {
                    exit_confirmed: error.process_exit_confirmed,
                    cancelled: matches!(error.reason, LaunchFailure::Cancelled),
                }
            })
    }
    fn recover(
        &mut self,
        identity: vpn::ProcessIdentity,
        cancelled: &AtomicBool,
    ) -> Result<vpn::RecoveryEvidence, vpn::RecoveryFailure> {
        let store = ProfileStore::open().map_err(|_| vpn::RecoveryFailure::Cleanup)?;
        recover_with(
            &store,
            identity,
            cancelled,
            &crate::service::Win32PathSecurityProbe,
        )
    }
}

pub(crate) fn recover_with(
    store: &ProfileStore,
    identity: vpn::ProcessIdentity,
    cancelled: &AtomicBool,
    probe: &dyn crate::service::PathSecurityProbe,
) -> Result<vpn::RecoveryEvidence, vpn::RecoveryFailure> {
    use std::sync::atomic::Ordering;
    if cancelled.load(Ordering::Acquire) {
        return Err(vpn::RecoveryFailure::Cancelled);
    }
    let evidence = crate::vpn_process::observe_exit(identity)?;
    if cancelled.load(Ordering::Acquire) {
        return Err(vpn::RecoveryFailure::Cancelled);
    }
    store
        .cleanup_run(identity.launch_id, probe)
        .map_err(|_| vpn::RecoveryFailure::Cleanup)?;
    Ok(evidence)
}
impl vpn::LiveSession for PreparedVpn {
    fn poll(&mut self) -> vpn::Observation {
        use ssk_vpnctl::ProcessStage;
        let snapshot = PreparedVpn::poll(self);
        match snapshot.stage {
            ProcessStage::Managing => vpn::Observation::Held,
            ProcessStage::Stopping => vpn::Observation::Stopping,
            ProcessStage::Terminating => vpn::Observation::Terminating,
            ProcessStage::TerminationUnconfirmed => vpn::Observation::Unconfirmed,
            ProcessStage::Exited => vpn::Observation::Exited {
                failed: snapshot.failure.is_some(),
            },
        }
    }
    fn stop(&mut self) {
        self.request_stop();
    }
    fn abort_and_confirm(&mut self) -> bool {
        PreparedVpn::abort_and_confirm(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_netd_helper::vpn::journal::{Event, Journal, Kind, MAX_RECORD_BYTES};
    #[test]
    fn durable_journal_roundtrip_torn_tail_and_oversized_records() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("journal");
        let open = || {
            std::fs::OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open(&path)
                .unwrap()
        };
        let mut journal = Journal::open(Box::new(FileJournal { file: open() })).unwrap();
        let status = vpn::Status {
            revision: 1,
            ..vpn::Status::default()
        };
        journal
            .append(Event {
                kind: Kind::Boot,
                actor: "service".into(),
                command: None,
                status: status.clone(),
                deployment: None,
            })
            .unwrap();
        drop(journal);
        let journal = Journal::open(Box::new(FileJournal { file: open() })).unwrap();
        assert_eq!(journal.last(), Some(&status));
        drop(journal);
        let good = std::fs::read(&path).unwrap();
        for bad in [
            vec![1],
            vec![8, 0, 0, 0, 1, 2],
            ((MAX_RECORD_BYTES + 1) as u32).to_le_bytes().to_vec(),
        ] {
            let mut bytes = good.clone();
            bytes.extend(bad);
            std::fs::write(&path, bytes).unwrap();
            assert!(Journal::open(Box::new(FileJournal { file: open() })).is_err());
        }
        std::fs::write(&path, &good).unwrap();
        let mut bytes = good;
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(Journal::open(Box::new(FileJournal { file: open() })).is_err());
    }
    #[test]
    fn control_pipe_admission_unions_domain_sids_without_broadening_authority() {
        let boundary: Vec<String> = vec!["S-1-5-21-1-2-3-1001".into()];
        let vpn = vec!["S-1-5-21-1-2-3-1002".into(), boundary[0].clone()];
        let sddl = crate::pipe::sddl_for_control_domains(Some(&boundary), &vpn).unwrap();
        assert_eq!(sddl.matches(&boundary[0]).count(), 1);
        assert!(sddl.contains(&vpn[0]));
        assert!(!sddl.contains(";;;IU)"));
        let fallback = crate::pipe::sddl_for_control_domains(None, &vpn).unwrap();
        assert!(fallback.contains(";;;IU)"));
        assert!(fallback.contains(&vpn[0]));
        assert!(fallback.ends_with("S:(ML;;NW;;;ME)"));
        assert!(
            crate::pipe::sddl_for_control_domains(None, &["evil)(A;;GA;;;WD)".into()]).is_err()
        );
    }
}
