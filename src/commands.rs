use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::anyhow;
use argon2::Argon2;
use protobuf::well_known_types::timestamp::Timestamp;
use protobuf::{Message, MessageField};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::digest::SHA256_OUTPUT_LEN;
use ring::error::Unspecified;
use ring::hkdf::{Salt, HKDF_SHA256};
use ring::rand::{SecureRandom, SystemRandom};

use crate::config::ConfigCommand;
use crate::create::CreateCommand;
use crate::open::OpenCommand;
use crate::parsing::Commands;
use crate::protos::rpdb::{Body, Directory, Header, RPDB};

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

    pub fn derive_key(key: &[u8], salt: &[u8]) -> anyhow::Result<LessSafeKey> {
        if salt.len() != SHA256_OUTPUT_LEN {
            return Err(anyhow!("Invalid salt length"));
        }

        let salt = Salt::new(HKDF_SHA256, salt);
        let prk = salt.extract(key);
        let okm = prk
            .expand(&INFO, HKDF_SHA256)
            .map_err(|_| anyhow!("Could not expand prk"))?;
        let mut buf = SaltBuffer::default();
        okm.fill(&mut buf)
            .map_err(|_| anyhow!("Could not fill buffer"))?;
        let unbound = UnboundKey::new(&AES_256_GCM, &buf)
            .map_err(|_| anyhow!("Could not create UnboundKey"))?;
        Ok(LessSafeKey::new(unbound))
    }

    pub fn get_unique_nonce() -> Result<NonceBuffer, Unspecified> {
        let mut buf = NonceBuffer::default();
        let rng = SystemRandom::new();
        rng.fill(&mut buf)?;
        Ok(buf)
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct VaultManager {
    header: Header,
    body: Body,
    master_hash: MasterBuffer,
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
    fn encrypt(&self) -> anyhow::Result<RPDB> {
        let key = KeyGen::derive_key(&self.master_hash, &self.header.master_salt)?;
        let nonce = Nonce::assume_unique_for_key(self.header.master_nonce.as_slice().try_into()?);
        let aad = Aad::from(self.header.write_to_bytes()?);
        let mut rpdb = RPDB::new();
        rpdb.body = self.body.write_to_bytes()?;
        key.seal_in_place_append_tag(nonce, aad, &mut rpdb.body)
            .map_err(|_| anyhow!("Could not seal body"))?;
        rpdb.header = MessageField::some(self.header.clone());
        Ok(rpdb)
    }

    pub fn initialize_from_file<P: AsRef<Path>>(
        &mut self,
        path: P,
        master_key: String,
    ) -> anyhow::Result<()> {
        let mut buf: Vec<u8> = vec![];
        let mut file = File::open(path)?;
        let bytes_read = file.read_to_end(&mut buf)?;
        if bytes_read == 0 {
            return Err(anyhow!("Read 0 bytes from file"));
        }
        let mut rpdb = RPDB::parse_from_bytes(&buf)?;
        self.header = rpdb
            .header
            .into_option()
            .ok_or(anyhow!("Could not parse header"))?;

        self.master_hash =
            KeyGen::encrypt_master(master_key, self.header.argon_salt.as_slice().try_into()?)?;

        let nonce = Nonce::assume_unique_for_key(self.header.master_nonce.as_slice().try_into()?);
        let key = KeyGen::derive_key(&self.master_hash, &self.header.master_salt)?;
        let aad = Aad::from(self.header.write_to_bytes()?);
        let decrypted_body = key
            .open_in_place(nonce, aad, &mut rpdb.body)
            .map_err(|_| anyhow!("Could not decrypt body"))?;
        self.body = Body::parse_from_bytes(decrypted_body)?;
        Ok(())
    }

    pub fn regenerate(&mut self, salts: Salts, master_key: String) -> anyhow::Result<()> {
        self.header.signature = 0x3af9c42;
        self.header.master_salt = salts.master_salt.to_vec();
        self.header.version = 0x0001;
        self.header.master_nonce = salts.master_nonce.to_vec();
        self.header.argon_salt = salts.argon_salt.to_vec();
        self.body.salt = salts.body_salt.to_vec();
        self.body.created_at = MessageField::some(Timestamp::now());
        self.body.last_modified = MessageField::some(Timestamp::now());
        self.master_hash = KeyGen::encrypt_master(master_key, &salts.argon_salt)?;
        Ok(())
    }

    pub fn save_new<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let mut file = File::create_new(path)?;
        file.write(&self.encrypt()?.write_to_bytes()?)?;
        Ok(())
    }

    pub fn add_directory(&mut self) -> anyhow::Result<()> {
        unimplemented!()
    }
}

pub struct DirectoryManager<'a> {
    directory: &'a Directory,
}

// Generator for nonces of
pub struct NonceGenerator {
    salt: SaltBuffer,
}

impl NonceGenerator {
    pub fn new(salt: SaltBuffer) -> Self {
        Self { salt }
    }

    pub fn generate(&self, directory_name: &str, index: u32) -> anyhow::Result<Nonce> {
        let mut key_buf = NonceBuffer::default();
        let mut salt: Vec<u8> = directory_name.as_bytes().to_vec();
        salt.extend_from_slice(&self.salt);
        Argon2::default()
            .hash_password_into(&index.to_le_bytes(), &self.salt, &mut key_buf)
            .map_err(|_| anyhow!("Could not generate argon2 hash"))?;
        Ok(Nonce::assume_unique_for_key(key_buf))
    }
}

#[cfg(test)]
mod test {
    use super::{Salts, VaultManager};
    use std::{env, fs::remove_file};

    #[test]
    fn test_init_save_open() {
        let master_password = "abcdefgh";
        let mut vm = VaultManager::default();
        let salts = Salts::new().unwrap();
        vm.regenerate(salts, String::from(master_password)).unwrap();

        let current_dir = env::current_dir().unwrap();
        let file_path = current_dir.join("test.rpdb");

        if file_path.exists() {
            remove_file(&file_path).unwrap();
        }

        vm.save_new(&file_path).unwrap();

        let mut vm1 = VaultManager::default();
        vm1.initialize_from_file(&file_path, String::from(master_password))
            .unwrap();

        assert_eq!(vm, vm1);
    }
}
