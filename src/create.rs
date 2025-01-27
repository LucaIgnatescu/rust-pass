use crate::{
    commands::{Executable, KeyGen, Salts, VaultManager},
    protos::rpdb::RPDB,
};
use anyhow::anyhow;
use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags};
use ring::{
    aead::{LessSafeKey, NONCE_LEN},
    digest::SHA256_OUTPUT_LEN,
    hkdf::{Salt, HKDF_SHA256},
    rand::{SecureRandom, SystemRandom},
};
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
        let rng = SystemRandom::new();
        let buf = read_password()?;
        let salts = Salts::new()?;
        let mut vm = VaultManager::default();
        vm.initialize_vault(salts)?;

        println!("vault: {:?}", vm);

        return Ok(());
    }
}

fn read_password() -> anyhow::Result<String> {
    let in_fd = stdin();
    let mut term = tcgetattr(&in_fd)?;
    print!("Please enter a master password: ");
    term.local_flags &= !LocalFlags::ECHO;
    tcsetattr(&in_fd, nix::sys::termios::SetArg::TCSANOW, &term)?;
    stdout().flush()?;
    let mut buf = String::new();
    in_fd.read_line(&mut buf)?;
    println!();
    Ok(buf)
}
