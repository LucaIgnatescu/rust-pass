use std::{
    env,
    fs::{create_dir_all, File},
    io::{Read, Write},
    path::PathBuf,
};

use crate::commands::Executable;
use crate::protos::config::Config;
use anyhow::anyhow;
use protobuf::Message;

pub struct ConfigCommand;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LocalConfig {
    chunk_size: u32,
    iterations: u32,
    memory: u32,
    parallelism: u32,
}

impl From<LocalConfig> for Config {
    fn from(value: LocalConfig) -> Self {
        let mut config = Self::new();
        config.chunk_size = value.chunk_size;
        config.iterations = value.iterations;
        config.memory = value.memory;
        config.parallelism = value.parallelism;
        return config;
    }
}

impl From<Config> for LocalConfig {
    fn from(value: Config) -> Self {
        Self {
            chunk_size: value.chunk_size,
            iterations: value.iterations,
            memory: value.memory,
            parallelism: value.parallelism,
        }
    }
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            chunk_size: 16,
            iterations: 2,
            memory: 16,
            parallelism: 1,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Option<()> {
        [
            self.parallelism,
            self.memory,
            self.iterations,
            self.chunk_size,
        ]
        .iter()
        .all(|&value| value != 0)
        .then(|| ())
    }
}

impl LocalConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn init_from_file(&mut self) -> anyhow::Result<()> {
        let config_dir = Self::get_config_location();
        let mut config_file = Self::get_config_file(&config_dir)?;
        let mut buf: Vec<u8> = vec![];
        config_file.read_to_end(&mut buf)?;
        let config = Config::parse_from_bytes(&buf)?;
        config.validate().ok_or(anyhow!("Invalid configuration"))?;
        *self = Self::from(config);
        Ok(())
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let config: Config = Config::from(*self);
        let buf = config.write_to_bytes()?;
        let mut config_file = Self::get_config_file(&Self::get_config_location())?;
        config_file
            .write(&buf)
            .map(|_| ())
            .map_err(|e| anyhow::Error::from(e))
    }

    fn get_config_location() -> PathBuf {
        #[cfg(target_os = "macos")] // TODO: Add more configs
        {
            let usr = env::var("HOME").unwrap(); // TODO: could be more graceful
            PathBuf::from(usr).join("Library/Application Support/RustPass")
        }
        //panic!("Could not retrieve config directory");
    }

    fn get_config_file(config_dir_path: &PathBuf) -> anyhow::Result<File> {
        if !config_dir_path.exists() {
            create_dir_all(config_dir_path)?;
        }
        let config_file_path = config_dir_path.join("config.txt");
        if config_file_path.exists() {
            return Ok(File::options()
                .read(true)
                .write(true)
                .open(config_file_path)?);
        }
        Ok(File::create_new(config_file_path)?)
    }
}

impl ConfigCommand {
    pub fn new() -> Self {
        ConfigCommand {}
    }
}
impl Executable for ConfigCommand {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_restore() {
        let mut want = LocalConfig::new();
        want.iterations = 5;
        want.save().unwrap();

        let mut config = LocalConfig::new();
        config.init_from_file().unwrap();
        assert_eq!(config, want);
    }
}
