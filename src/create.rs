use crate::{
    commands::{Executable, KeyGen, Salts, VaultManager},
    display::TerminalControl,
};
use anyhow::anyhow;
use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags};
use std::{
    io::{stdin, stdout, Write},
    path::Path,
};

pub struct CreateCommand {
    name: String,
    path: String,
}

impl CreateCommand {
    pub fn new(name: String, path: String) -> Self {
        Self { name, path }
    }
}

impl Executable for CreateCommand {
    fn execute(&self) -> anyhow::Result<()> {
        let file_path = Path::new(&self.path);
        if file_path.is_file() {
            return Err(anyhow!("Could not create database - file already exists!"));
        }

        let buf = read_password()?;
        let mut vm = VaultManager::default();
        vm.regenerate(buf)?;

        return Ok(());
    }
}

fn read_password() -> anyhow::Result<String> {
    let term = TerminalControl::new()?;
    term.disable_echo()?;
    print!("Please enter a master password: ");
    stdout().flush()?;

    let mut buf = String::new();
    stdin().read_line(&mut buf)?;
    println!();
    Ok(buf)
}
