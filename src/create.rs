use crate::{
    commands::{Executable, KeyGen},
    protos::rpdb::{Body, Header, RPDB},
};
use anyhow::anyhow;
use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags};
use protobuf::{well_known_types::timestamp::Timestamp, Message, MessageField};
use ring::{
    aead::{Aad, LessSafeKey, Nonce, NONCE_LEN},
    digest::SHA256_OUTPUT_LEN,
    error::Unspecified,
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

struct EncryptionInfo<'a> {
    key: &'a LessSafeKey,
    nonce: &'a [u8; NONCE_LEN],
    salt: &'a [u8; SHA256_OUTPUT_LEN],
}

impl<'a> EncryptionInfo<'a> {
    pub fn new(
        key: &'a LessSafeKey,
        nonce: &'a [u8; NONCE_LEN],
        salt: &'a [u8; SHA256_OUTPUT_LEN],
    ) -> Self {
        Self { key, nonce, salt }
    }
}

impl CreateCommand {
    pub fn new(name: String, path: String) -> Self {
        Self { name, path }
    }

    fn initialize_vault(info: EncryptionInfo) -> anyhow::Result<RPDB> {
        let rng = ring::rand::SystemRandom::new();
        let mut header = Header::new();
        header.signature = 0x3af9c42;

        let mut salt = vec![0u8; 32];
        rng.fill(&mut salt)
            .map_err(|_| anyhow!("Could not generate master salt"))?;

        header.master_salt = salt;
        header.version = 0x0001;
        header.master_nonce = info.nonce.into();
        header.argon_salt = info.salt.into();

        let mut body = Body::new();
        let mut salt = vec![0u8; 32];
        rng.fill(&mut salt)
            .map_err(|_| anyhow!("Could not generate body salt"))?;

        body.created_at = MessageField::some(Timestamp::now());
        body.last_modified = MessageField::some(Timestamp::now());

        let mut rpdb = RPDB::new();
        let nonce = Nonce::assume_unique_for_key(info.nonce.clone());
        let buf = header.write_to_bytes()?;

        info.key
            .seal_in_place_append_tag(nonce, Aad::from(buf), &mut rpdb.body)
            .map_err(|_| anyhow!("Could not seal header"))?;
        rpdb.header = MessageField::some(header);

        Ok(rpdb)
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
        let mut salt_buf = [0u8; SHA256_OUTPUT_LEN];
        rng.fill(&mut salt_buf)
            .map_err(|_| anyhow!("Could not generate main salt"))?;
        let salt = Salt::new(HKDF_SHA256, &salt_buf);

        let argon_key = KeyGen::encrypt_master(buf)?;
        let key = KeyGen::derive_key(&argon_key.key, &salt)
            .map_err(|_| anyhow!("Could not generate main key"))?;

        let nonce = KeyGen::get_unique_nonce().map_err(|_| anyhow!("Could not generate nonce"))?;
        let info = EncryptionInfo::new(&key, &nonce, &argon_key.salt);
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
