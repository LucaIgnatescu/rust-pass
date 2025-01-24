use super::Executable;

pub struct ConfigCommand {}

impl ConfigCommand {
    pub fn new() -> Self {
        ConfigCommand {}
    }
}

impl Executable for ConfigCommand {
    fn execute(&self) {
        println!("Executing config...");
    }
}
