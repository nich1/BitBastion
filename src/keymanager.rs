use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub fn enter_key(key: &str) {
    // Generates key
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let result = hasher.finalize();

    let strpath = format!("Key/enckey.bin",);
    let path = Path::new(&strpath);
    if path.exists() {
        println!("A key has already been generated and can not be overwritten.");
    } else {
        if let Err(e) = fs::write(&strpath, result) {
            println!("Error writing to key file: {}", e);
        } else {
            println!("\tAdded hex to key file:\n\t{:x} ", result);
        }
    }
}

pub fn check_key(input: &str) -> bool {
    // Convert input into SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();

    // Convert the computed hash to a hexadecimal string
    let hex_result = result
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();

    let keystrpath = "Key/enckey.bin";
    let path = Path::new(&keystrpath);

    if path.exists() {
        // Read the binary data from the file
        match fs::read(&keystrpath) {
            Ok(bin_data) => {
                // Convert each byte in the Vec<u8> to a hex string
                let bin_hex: String = bin_data
                    .iter() // Iterate over each byte in the Vec<u8>
                    .map(|byte| format!("{:02x}", byte)) // Convert byte to hex
                    .collect(); // Collect as a single String

                // Compare the computed hex hash with the hex data read from the file
                if hex_result == bin_hex {
                    true
                } else {
                    false
                }
            }
            Err(e) => {
                println!("Error reading key: {}", e);
                false
            }
        }
    } else {
        println!("A key has not been generated yet");
        false
    }
}
