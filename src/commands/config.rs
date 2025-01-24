use super::Executable;
use anyhow::Result;

pub struct ConfigCommand {}

impl ConfigCommand {
    pub fn new() -> Self {
        ConfigCommand {}
    }
}

impl Executable for ConfigCommand {}
