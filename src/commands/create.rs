use super::Executable;
use anyhow::anyhow;
use std::path::Path;

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
            return Err(anyhow!("File already exists!"));
        }
        return Ok(());
    }
}
