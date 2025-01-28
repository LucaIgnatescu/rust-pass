use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{anyhow, Ok, Result};
use argon2::Argon2;
use protobuf::{well_known_types::timestamp::Timestamp, Message, MessageField};
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN},
    digest::SHA256_OUTPUT_LEN,
    hkdf::{Salt, HKDF_SHA256},
    rand::{SecureRandom, SystemRandom},
};

use crate::protos::rpdb::Record;
use crate::{
    config::ConfigCommand,
    create::CreateCommand,
    open::OpenCommand,
    parsing::Commands,
    protos::rpdb::{Body, Directory, Header, RPDB},
};

pub trait Executable {
    fn execute(&self) -> Result<()> {
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
pub type KeyBuffer = [u8; SHA256_OUTPUT_LEN];

fn erase<T: Into<Vec<u8>>>(s: T) {
    let mut buffer: Vec<u8> = s.into();
    buffer.fill(0);
}

impl KeyGen {
    pub fn encrypt_master(mut master_key: String, salt: &SaltBuffer) -> Result<KeyBuffer> {
        let mut key = SaltBuffer::default();
        Argon2::default()
            .hash_password_into(&master_key.as_bytes(), salt, &mut key)
            .map_err(|_| anyhow!("Could not generate argon2 hash"))?;

        erase(master_key);
        Ok(key)
    }

    pub fn derive_key(key: &[u8], salt: &[u8]) -> Result<LessSafeKey> {
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

    pub fn get_unique_nonce() -> Result<NonceBuffer> {
        let mut buf = NonceBuffer::default();
        let rng = SystemRandom::new();
        rng.fill(&mut buf)
            .map_err(|_| anyhow!("Coult not generate nonce"))?;
        Ok(buf)
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct VaultManager {
    header: Header,
    body: Body,
    master_hash: KeyBuffer,
}

#[derive(Default, Debug)]
pub struct Salts {
    master_nonce: NonceBuffer,
    master_salt: SaltBuffer,
    body_salt: SaltBuffer,
    argon_salt: SaltBuffer,
}

impl Salts {
    pub fn new() -> Result<Self> {
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
    fn encrypt(&self) -> Result<RPDB> {
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
    ) -> Result<()> {
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

    pub fn regenerate(&mut self, master_key: String) -> Result<()> {
        let salts = Salts::new()?;
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

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        if let Some(path) = path.as_ref().parent() {
            if !path.exists() {
                create_dir_all(path)?;
            }
        }
        let mut file = File::create(path)?;
        file.write(&self.encrypt()?.write_to_bytes()?)?;
        Ok(())
    }

    pub fn add_directory(&mut self, name: &str) -> () {
        let mut dir = Directory::new();
        dir.name = name.into();
        self.body.directories.push(dir);
    }

    pub fn remove_directory(&mut self, name: &str) -> Result<()> {
        if let Some(index) = self
            .body
            .directories
            .iter()
            .position(|dir| dir.name == name)
        {
            self.body.directories.remove(index);
            return Ok(());
        }
        Err(anyhow!("Directory does not exist"))
    }

    pub fn add_key(&mut self, dir_name: &str, key_name: &str, key_val: &str) -> Result<()> {
        if let Some(dir) = self
            .body
            .directories
            .iter_mut()
            .find(|dir| dir.name == dir_name)
        {
            let mut dm = DirectoryManager::new(
                dir,
                self.body.salt.as_slice().try_into()?,
                &self.master_hash,
            );
            return dm.add_record(key_name, key_val);
        }
        Err(anyhow!("Could not locate directory"))
    }

    pub fn remove_key(&mut self, dir_name: &str, key_name: &str) -> Result<()> {
        if let Some(dir) = self
            .body
            .directories
            .iter_mut()
            .find(|dir| dir.name == dir_name)
        {
            let mut dm = DirectoryManager::new(
                dir,
                self.body.salt.as_slice().try_into()?,
                &self.master_hash,
            );
            return dm.remove_record(key_name);
        }
        Err(anyhow!("Could not locate directory"))
    }

    pub fn get_key(&mut self, dir_name: &str, key_name: &str) -> Result<String> {
        if let Some(dir) = self
            .body
            .directories
            .iter_mut()
            .find(|dir| dir.name == dir_name)
        {
            let mut dm = DirectoryManager::new(
                dir,
                self.body.salt.as_slice().try_into()?,
                &self.master_hash,
            );
            return dm.get_record(key_name);
        }
        Err(anyhow!("Could not locate directory"))
    }
}

struct DirectoryManager<'a> {
    dir: &'a mut Directory,
    salt: &'a SaltBuffer,
    master_key: &'a KeyBuffer,
}

impl<'a> DirectoryManager<'a> {
    pub fn new(dir: &'a mut Directory, salt: &'a SaltBuffer, key: &'a KeyBuffer) -> Self {
        Self {
            dir,
            salt,
            master_key: key,
        }
    }

    pub fn add_record(&mut self, name: &str, key_val: &str) -> Result<()> {
        let nonce_buf = generate_nonce_buf(self.salt, &self.dir.name, self.dir.records.len())?;
        let key = KeyGen::derive_key(self.master_key, self.salt)?;
        let nonce = Nonce::assume_unique_for_key(nonce_buf);
        let aad = Aad::from(name);
        let mut buf: Vec<u8> = key_val.into();
        key.seal_in_place_append_tag(nonce, aad, &mut buf)
            .map_err(|_| anyhow!("Could not seal key"))?;
        let mut record = Record::new();
        record.name = name.into();
        record.nonce = nonce_buf.into();
        record.data = buf.into();

        self.dir.records.push(record);

        Ok(())
    }

    pub fn get_record(&mut self, name: &str) -> Result<String> {
        let index = self
            .dir
            .records
            .iter()
            .position(|record| record.name == name)
            .ok_or(anyhow!("Key does not exist"))?;

        let record = &self.dir.records[index];
        let nonce = Nonce::assume_unique_for_key(record.nonce.as_slice().try_into()?);
        let aad = Aad::from(name);
        let key = KeyGen::derive_key(self.master_key, self.salt)?;
        let mut buf: Vec<u8> = record.data.clone();

        let decrypted = key
            .open_in_place(nonce, aad, &mut buf)
            .map_err(|_| anyhow!("Could not open key"))?;

        Ok(String::from_utf8(decrypted.to_vec())?)
    }
    pub fn remove_record(&mut self, name: &str) -> Result<()> {
        let index = self
            .dir
            .records
            .iter()
            .position(|record| record.name == name)
            .ok_or(anyhow!("Key does not exist"))?;
        self.dir.records.remove(index);
        Ok(())
    }

    pub fn rename(&mut self, new_name: &str) {
        self.dir.name = new_name.into();
    }
}

pub fn generate_nonce_buf(
    salt: &SaltBuffer,
    directory_name: &str,
    index: usize,
) -> Result<NonceBuffer> {
    let mut key_buf = NonceBuffer::default();
    let mut salt_buf: Vec<u8> = directory_name.as_bytes().to_vec();
    salt_buf.extend_from_slice(salt);
    Argon2::default()
        .hash_password_into(&index.to_le_bytes(), salt, &mut key_buf)
        .map_err(|_| anyhow!("Could not generate argon2 hash"))?;
    Ok(key_buf)
}

#[cfg(test)]
mod test {
    use super::VaultManager;
    use std::{env, fs::remove_file};

    #[test]
    fn test_init_save_open() {
        let master_password = "abcdefgh";
        let mut vm = VaultManager::default();
        vm.regenerate(String::from(master_password)).unwrap();

        let current_dir = env::current_dir().unwrap();
        let file_path = current_dir.join("test.rpdb");

        if file_path.exists() {
            remove_file(&file_path).unwrap();
        }

        vm.save(&file_path).unwrap();

        let mut vm1 = VaultManager::default();
        vm1.initialize_from_file(&file_path, String::from(master_password))
            .unwrap();

        assert_eq!(vm, vm1);
    }
    #[test]
    fn test_directory_add_key() {
        let master_password = "abcdefgh";
        let dir_name = "test";
        let mut vm = VaultManager::default();
        vm.regenerate(String::from(master_password)).unwrap();
        vm.add_directory(&dir_name);
        vm.add_key(&dir_name, "aaa", "abc").unwrap();

        let buf = vm.get_key(dir_name, "aaa").unwrap();

        assert_eq!(buf, "abc");

        vm.remove_key(dir_name, "aaa").unwrap();
        assert!(vm.get_key(dir_name, "aaa").is_err());
        vm.remove_directory(dir_name).unwrap();
    }
}
