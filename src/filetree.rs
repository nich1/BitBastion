use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
// Or `Aes128Gcm`
use std::fs;
use std::io::{Read, Write};
use rand::RngCore;
use std::path::Path;

use crate::keymanager;


// Encrypt a single file using AES-GCM
fn encrypt_file(file_path: &Path, key: &str) {
    // Validate key
    if !keymanager::check_key(key) {
        println!("Invalid key");
    }

    // Read the key bytes
    let key_bytes = fs::read("Key/enckey.bin").expect("Error reading key");

    // Ensure the key is 32 bytes for AES-256
    if key_bytes.len() != 32 {
        println!("Key must be exactly 32 bytes long for AES-256.");
        return;
    }

    // Create the usable key from the byte array
    let usable_key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    // Read the file
    let mut file_data = Vec::new();
    let mut file = fs::File::open(file_path).expect("Error opening  file");
    file.read_to_end(&mut file_data).expect("Error reading file");

    // Generate a random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Initialize AES-GCM
    let cipher = Aes256Gcm::new_from_slice(usable_key).expect("invalid key length");

    // Encrypt the data
    let ciphertext = cipher.encrypt(nonce, file_data.as_ref())
        .expect("encryption failure!");

    // Write the encrypted data back to the file
    let mut output_file = fs::File::create(file_path).expect("Error creating file");
    output_file.write_all(&nonce_bytes).expect("Error writing to file"); // Store the nonce
    output_file.write_all(&ciphertext).expect("Error writing to file");  // Store the ciphertext

}

// Recursively encrypt all files in a folder
pub fn encrypt_folder(folder_path: &Path, key: &str)  {
    for entry in fs::read_dir(folder_path).expect("Error reading directory") {
        let entry = entry.expect("Error getting entry");
        let path = entry.path();
        if path.is_dir() {
            // Recursively encrypt subfolders
            encrypt_folder(&path, key);
        } else {
            // Encrypt the file
            encrypt_file(&path, key);
        }
    }
}

// Decrypt a single file using AES-GCM
fn decrypt_file(file_path: &Path, key: &str) {
    // Validate key
    if !keymanager::check_key(key) {
        println!("Invalid key");
    }

    // Read the key bytes
    let key_bytes = fs::read("Key/enckey.bin").expect("Error reading key");

    // Ensure the key is 32 bytes for AES-256
    if key_bytes.len() != 32 {
        println!("Key must be exactly 32 bytes long for AES-256.");
        return
    }

    // Create the usable key from the byte array
    let usable_key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    // Read the encrypted file
    let mut file = fs::File::open(file_path).expect("Error opening file");
    let mut nonce_bytes = [0u8; 12];
    file.read_exact(&mut nonce_bytes).expect("Error reading"); // Read the nonce

    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext).expect("Error reading"); // Read the rest of the file as ciphertext

    // Initialize AES-GCM
    let cipher = Aes256Gcm::new_from_slice(usable_key).expect("Encryption err");

    // Decrypt the data
    let decrypted_data = cipher.decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref()).expect("Err");
    // Write the decrypted data back to the file
    let mut output_file = fs::File::create(file_path).expect("Err");
    output_file.write_all(&decrypted_data).expect("Err writing");

}

// Recursively decrypt all files in a folder
pub fn decrypt_folder(folder_path: &Path, key: &str) {
    for entry in fs::read_dir(folder_path).expect("Error reading dir") {
        let entry = entry.expect("Entry err");
        let path = entry.path();
        if path.is_dir() {
            // Recursively decrypt subfolders
            decrypt_folder(&path, key);
        } else {
            // Decrypt the file
            decrypt_file(&path, key);
        }
    }
}