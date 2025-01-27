use ring::aead::{LessSafeKey, Nonce, NonceSequence, UnboundKey, AES_128_GCM, NONCE_LEN};
use ring::digest::SHA256_OUTPUT_LEN;
use ring::error::Unspecified;
use ring::hkdf::{Salt, HKDF_SHA256};

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

struct Keygen;
static INFO: [&[u8]; 1] = ["".as_bytes()]; // TODO: Look into this

impl Keygen {
    pub fn get_main_key(master_key: &String, salt: Salt) -> Result<LessSafeKey, Unspecified> {
        let prk = salt.extract(master_key.clone().as_bytes());
        let okm = prk.expand(&INFO, HKDF_SHA256)?;
        let mut buf = vec![0u8; SHA256_OUTPUT_LEN];
        okm.fill(&mut buf)?;
        let unbound = UnboundKey::new(&AES_128_GCM, &buf)?;
        Ok(LessSafeKey::new(unbound))
    }
}
