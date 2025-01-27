use anyhow::anyhow;
use argon2::Argon2;
use ring::aead::{LessSafeKey, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::digest::SHA256_OUTPUT_LEN;
use ring::error::Unspecified;
use ring::hkdf::{Salt, HKDF_SHA256};
use ring::rand::{SecureRandom, SystemRandom};

use crate::config::ConfigCommand;
use crate::create::CreateCommand;
use crate::open::OpenCommand;
use crate::parsing::Commands;

pub trait Executable {
    fn execute(&self) -> anyhow::Result<()> {
        println!("Executing...");
        Ok(())
    }
}

pub fn command_factory(command: Commands) -> Box<dyn Executable> {
    match command {
        Commands::Create { name, path } => Box::new(CreateCommand::new(name, path)),
        Commands::Open { file_path } => Box::new(OpenCommand::new(file_path)),
        Commands::Config => Box::new(ConfigCommand::new()),
    }
}

pub struct KeyGen;

static INFO: [&[u8]; 1] = ["".as_bytes()]; // TODO: Look into this

pub struct ArgonOutput {
    pub key: [u8; SHA256_OUTPUT_LEN],
    pub salt: [u8; SHA256_OUTPUT_LEN],
}

impl KeyGen {
    pub fn encrypt_master(mut master_key: String) -> anyhow::Result<ArgonOutput> {
        let mut salt = [0u8; SHA256_OUTPUT_LEN];
        let rng = SystemRandom::new();
        rng.fill(&mut salt)
            .map_err(|_| anyhow!("Could not generate salt"))?;
        let mut key = [0u8; SHA256_OUTPUT_LEN];
        Argon2::default()
            .hash_password_into(&master_key.as_bytes(), &salt, &mut key)
            .map_err(|_| anyhow!("Could not generate argon2 hash"))?;

        unsafe {
            let buffer = master_key.as_mut_vec();
            buffer.fill(0);
        }

        Ok(ArgonOutput { key, salt })
    }

    pub fn derive_key(key: &[u8], salt: &Salt) -> Result<LessSafeKey, Unspecified> {
        let prk = salt.extract(key);
        let okm = prk.expand(&INFO, HKDF_SHA256)?;
        let mut buf = vec![0u8; SHA256_OUTPUT_LEN];
        okm.fill(&mut buf)?;
        let unbound = UnboundKey::new(&AES_256_GCM, &buf)?;
        Ok(LessSafeKey::new(unbound))
    }

    pub fn get_unique_nonce() -> Result<[u8; NONCE_LEN], Unspecified> {
        let mut buf = [0u8; NONCE_LEN];
        let rng = SystemRandom::new();
        rng.fill(&mut buf)?;
        Ok(buf)
    }
}
