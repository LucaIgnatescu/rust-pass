use super::Executable;

pub struct OpenCommand {
    file_path: String,
}

impl OpenCommand {
    pub fn new(file_path: String) -> Self {
        Self { file_path }
    }
}

impl Executable for OpenCommand {
    fn execute(&self) {
        println!("Executing open...");
    }
}
