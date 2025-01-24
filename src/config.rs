use crate::commands::Executable;

pub struct ConfigCommand {}

impl ConfigCommand {
    pub fn new() -> Self {
        ConfigCommand {}
    }
}

impl Executable for ConfigCommand {}
