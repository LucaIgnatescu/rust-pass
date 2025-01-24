use rand::prelude::*;

pub struct Rng {}

impl Rng {
    pub fn get_master_salt() -> [u8; 32] {
        random()
    }

    pub fn get_iv() -> [u8; 12] {
        random()
    }

    pub fn get_kdf_salt() -> [u8; 8] {
        random()
    }
}
