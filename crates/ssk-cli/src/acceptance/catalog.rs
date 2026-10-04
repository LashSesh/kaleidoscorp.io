use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Cli,
    Acl,
    Journal,
    Process,
    Network,
    Fault,
    Operator,
}

#[derive(Clone, Serialize)]
pub struct Case {
    pub id: String,
    pub required_evidence: Vec<EvidenceKind>,
    pub pass_available: bool,
}

pub fn catalog() -> Vec<Case> {
    use EvidenceKind::*;
    let groups: &[(&str, &[&[EvidenceKind]])] = &[
        (
            "H",
            &[
                &[Cli, Acl, Process],
                &[Cli, Process],
                &[Cli, Operator],
                &[Journal, Process, Fault],
                &[Cli, Journal, Process, Fault],
                &[Cli, Journal, Process],
                &[Cli, Journal, Process, Fault],
                &[Cli, Process],
                &[Cli, Journal, Fault],
                &[Cli, Journal, Fault],
                &[Cli, Acl, Journal],
                &[Cli, Journal, Operator],
                &[Cli, Process, Fault],
                &[Network, Process],
            ],
        ),
        (
            "J",
            &[
                &[Journal, Acl],
                &[Journal, Fault],
                &[Cli, Journal],
                &[Cli, Journal, Acl],
                &[Cli, Journal],
                &[Journal, Process],
                &[Journal, Operator],
            ],
        ),
        (
            "D",
            &[
                &[Cli, Acl, Operator],
                &[Cli, Acl],
                &[Cli, Journal],
                &[Cli, Journal],
                &[Cli, Journal, Fault],
                &[Cli, Acl, Fault],
                &[Cli, Journal],
                &[Operator],
            ],
        ),
        (
            "C",
            &[
                &[Cli, Acl, Operator],
                &[Cli, Process, Operator],
                &[Cli, Journal, Operator],
                &[Cli, Journal],
                &[Cli, Journal, Fault],
                &[Cli, Journal],
                &[Cli, Journal],
                &[Operator, Acl],
            ],
        ),
        (
            "F",
            &[
                &[Cli, Acl, Operator],
                &[Cli, Journal],
                &[Cli, Journal, Process],
                &[Cli, Journal, Fault],
                &[Cli, Acl, Journal],
                &[Cli, Journal],
            ],
        ),
        (
            "B",
            &[
                &[Cli, Acl, Operator],
                &[Cli, Operator],
                &[Cli, Journal],
                &[Cli, Journal],
                &[Cli, Fault],
                &[Operator, Acl],
            ],
        ),
    ];
    groups
        .iter()
        .flat_map(|(group, rows)| {
            rows.iter().enumerate().map(move |(i, kinds)| {
                let id = format!("{group}{:02}", i + 1);
                let pass_available = !matches!(id.as_str(), "J07" | "D08" | "B06");
                Case {
                    id,
                    required_evidence: kinds.to_vec(),
                    pass_available,
                }
            })
        })
        .collect()
}
