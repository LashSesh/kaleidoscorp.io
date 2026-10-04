use super::*;

struct Child {
    exited: bool,
    fail_termination: bool,
    fail_observation: bool,
    terminated: bool,
}
impl ChildProcess for Child {
    fn id(&self) -> u32 {
        1
    }
    fn try_wait(&mut self) -> io::Result<Option<u32>> {
        if self.fail_observation {
            Err(io::ErrorKind::PermissionDenied.into())
        } else {
            Ok(self.exited.then_some(23))
        }
    }
    fn terminate(&mut self) -> io::Result<()> {
        self.terminated = true;
        if self.fail_termination {
            Err(io::ErrorKind::PermissionDenied.into())
        } else {
            self.exited = true;
            Ok(())
        }
    }
}
#[test]
fn already_exited_child_is_not_terminated_again() {
    let mut child = Child {
        exited: true,
        fail_termination: false,
        fail_observation: false,
        terminated: false,
    };
    let report = cleanup(&mut child);
    assert!(report.exit_observed);
    assert!(!report.termination_requested);
    assert!(!child.terminated);
}
#[test]
fn termination_requires_a_separate_exit_observation() {
    for failed_query in [false, true] {
        let mut child = Child {
            exited: false,
            fail_termination: false,
            fail_observation: failed_query,
            terminated: false,
        };
        let report = cleanup(&mut child);
        assert!(report.termination_requested);
        assert_eq!(report.termination_call_succeeded, Some(true));
        assert_eq!(report.exit_observed, !failed_query);
    }
}
#[test]
fn failed_termination_and_unknown_exit_remain_visible() {
    let mut child = Child {
        exited: false,
        fail_termination: true,
        fail_observation: true,
        terminated: false,
    };
    let report = cleanup(&mut child);
    assert!(report.termination_requested);
    assert_eq!(report.termination_call_succeeded, Some(false));
    assert!(!report.exit_observed);
    assert_eq!(report.exit_code, None);
}
