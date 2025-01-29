use crate::{
    commands::{Executable, VaultManager},
    display::TerminalControl,
};
use anyhow::{anyhow, Result};
use std::{
    io::{stdin, stdout, Write},
    path::PathBuf,
    str::FromStr,
};

pub struct CreateCommand {
    name: String,
    dir: String,
}

impl CreateCommand {
    pub fn new(name: String, dir: String) -> Self {
        Self { name, dir }
    }
}

impl Executable for CreateCommand {
    fn execute(&self) -> Result<()> {
        let path = self.generate_path()?;
        let buf = read_password()?;
        let mut vm = VaultManager::default();
        vm.regenerate(buf)?;
        vm.save(path)?;
        println!("Vault succesfully created");
        Ok(())
    }
}

impl CreateCommand {
    fn generate_path(&self) -> Result<PathBuf> {
        let mut buf = PathBuf::from_str(&self.dir)?;
        if !buf.is_dir() {
            return Err(anyhow!("Directory does not exist."));
        }
        buf = buf.canonicalize()?;
        buf.push(format!("{}.rpdb", &self.name));
        Ok(buf)
    }
}

fn read_password() -> Result<String> {
    let term = TerminalControl::new()?;
    term.disable_echo()?;
    print!("Please enter a master password: ");
    stdout().flush()?;

    let mut buf = String::new();
    stdin().read_line(&mut buf)?;
    println!();
    Ok(buf)
}
