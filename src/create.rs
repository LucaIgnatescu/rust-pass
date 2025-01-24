use crate::{
    commands::Executable,
    protos::{header::Header, rpdb::RPDB},
};
use anyhow::anyhow;
use std::{fs::File, path::Path};

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
        let f =
            File::create_new(file_path).map_err(|e| anyhow!("Could not create database - {}", e));

        return Ok(());
    }
}

//fn create_vault() -> anyhow::Result<RPDB> {
//    let mut header = Header::new();
//    header.signature = 0x3AF9C42;
//    header.version = 0x0001;
//}
