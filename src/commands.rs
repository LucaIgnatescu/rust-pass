use std::fs::File;
use std::path::PathBuf;

use anyhow::anyhow;
use argon2::Argon2;
use protobuf::well_known_types::timestamp::Timestamp;
use protobuf::MessageField;
use ring::aead::{LessSafeKey, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::digest::SHA256_OUTPUT_LEN;
use ring::error::Unspecified;
use ring::hkdf::{Salt, HKDF_SHA256};
use ring::rand::{SecureRandom, SystemRandom};

use crate::config::ConfigCommand;
use crate::create::CreateCommand;
use crate::open::OpenCommand;
use crate::parsing::Commands;
use crate::protos::rpdb::{Body, Header};

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

pub type SaltBuffer = [u8; SHA256_OUTPUT_LEN];
pub type NonceBuffer = [u8; NONCE_LEN];
pub type MasterBuffer = [u8; SHA256_OUTPUT_LEN];

impl KeyGen {
    pub fn encrypt_master(
        mut master_key: String,
        salt: &SaltBuffer,
    ) -> anyhow::Result<MasterBuffer> {
        let mut key = SaltBuffer::default();
        Argon2::default()
            .hash_password_into(&master_key.as_bytes(), salt, &mut key)
            .map_err(|_| anyhow!("Could not generate argon2 hash"))?;

        unsafe {
            let buffer = master_key.as_mut_vec();
            buffer.fill(0);
        }
        Ok(key)
    }

    pub fn derive_key(key: &[u8], salt: &SaltBuffer) -> Result<LessSafeKey, Unspecified> {
        let salt = Salt::new(HKDF_SHA256, salt);
        let prk = salt.extract(key);
        let okm = prk.expand(&INFO, HKDF_SHA256)?;
        let mut buf = SaltBuffer::default();
        okm.fill(&mut buf)?;
        let unbound = UnboundKey::new(&AES_256_GCM, &buf)?;
        Ok(LessSafeKey::new(unbound))
    }

    pub fn get_unique_nonce() -> Result<NonceBuffer, Unspecified> {
        let mut buf = NonceBuffer::default();
        let rng = SystemRandom::new();
        rng.fill(&mut buf)?;
        Ok(buf)
    }
}

#[derive(Debug, Default)]
pub struct VaultManager {
    header: Header,
    body: Body,
}

#[derive(Default, Debug)]
pub struct Salts {
    master_nonce: NonceBuffer,
    master_salt: SaltBuffer,
    body_salt: SaltBuffer,
    argon_salt: SaltBuffer,
}

impl Salts {
    pub fn new() -> anyhow::Result<Self> {
        let rng = SystemRandom::new();

        let mut instance = Self::default();
        rng.fill(&mut instance.master_salt)
            .map_err(|_| anyhow!("Could not generate salt"))?;
        rng.fill(&mut instance.body_salt)
            .map_err(|_| anyhow!("Could not generate salt"))?;
        rng.fill(&mut instance.argon_salt)
            .map_err(|_| anyhow!("Could not generate salt"))?;
        rng.fill(&mut instance.master_nonce)
            .map_err(|_| anyhow!("Could not generate nonce"))?;

        Ok(instance)
    }
}

impl VaultManager {
    pub fn initialize_vault(&mut self, salts: Salts) -> anyhow::Result<()> {
        self.header.signature = 0x3af9c42;

        self.header.master_salt = salts.master_salt.to_vec();
        self.header.version = 0x0001;
        self.header.master_nonce = salts.master_nonce.to_vec();
        self.header.argon_salt = salts.argon_salt.to_vec();

        self.body.salt = salts.body_salt.to_vec();
        self.body.created_at = MessageField::some(Timestamp::now());
        self.body.last_modified = MessageField::some(Timestamp::now());

        //let mut rpdb = RPDB::new();
        //let nonce = Nonce::assume_unique_for_key(*salts.master_nonce);
        //let buf = header.write_to_bytes()?;

        //let key = KeyGen::derive_key(master_hash, salts.master_salt)?;
        //key.seal_in_place_append_tag(nonce, Aad::from(buf), &mut rpdb.body)
        //    .map_err(|_| anyhow!("Could not seal header"))?;
        //rpdb.header = MessageField::some(header);

        Ok(())
    }

    pub fn save(&self, location: PathBuf) -> anyhow::Result<()> {
        unimplemented!()
    }

    pub fn regenerate(&mut self) -> anyhow::Result<()> {
        unimplemented!()
    }

    pub fn add_directory(&mut self) -> anyhow::Result<()> {
        unimplemented!()
    }
}

impl From<File> for VaultManager {
    fn from(value: File) -> Self {
        unimplemented!()
    }
}
