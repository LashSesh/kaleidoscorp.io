#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use ssk_types::{Locator, LocatorId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocatorPool {
    pub locators: Vec<Locator>,
}

impl LocatorPool {
    #[must_use]
    pub fn new(locators: Vec<Locator>) -> Self {
        Self { locators }
    }

    #[must_use]
    pub fn get(&self, id: &LocatorId) -> Option<Locator> {
        self.locators.iter().find(|l| &l.id == id).cloned()
    }

    #[must_use]
    pub fn select_first_viable(&self) -> Option<Locator> {
        self.locators
            .iter()
            .find(|l| l.trusted && l.risk_score <= 70)
            .cloned()
    }
}
