use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use crate::keymanager;

// Marker to indicate the file is encrypted
const ENCRYPTION_MARKER: &[u8] = b"ENCFILE";

// Encrypt a single file using AES-GCM
fn encrypt_file(file_path: &Path, key: &str) {
    // Validate key
    if !keymanager::check_key(key) {
        println!("Invalid key");
        return;
    }

    // Open the file to check for the marker
    let mut file = fs::File::open(file_path).expect("Error opening file");

    // Get the file size
    let file_size = file.metadata().expect("Error getting file metadata").len();

    // Check if the file is large enough to contain the marker (7 bytes)
    if file_size >= ENCRYPTION_MARKER.len() as u64 {
        // Read the first 7 bytes to check for the encryption marker
        let mut marker = [0u8; 7];
        if let Err(_) = file.read_exact(&mut marker) {
            println!("Error reading marker. Skipping file.");
            return;
        }

        // If the file already contains the marker, skip encryption
        if &marker == ENCRYPTION_MARKER {
            println!("File is already encrypted. Skipping: {:?}", file_path);
            return;
        }
    }

    // Reopen the file to read the data (since the file cursor has already moved)
    let mut file_data = Vec::new();
    file = fs::File::open(file_path).expect("Error opening file");
    file.read_to_end(&mut file_data)
        .expect("Error reading file");

    // Read the key bytes
    let key_bytes = fs::read("Key/enckey.bin").expect("Error reading key");

    // Ensure the key is 32 bytes for AES-256
    if key_bytes.len() != 32 {
        println!("Key must be exactly 32 bytes long for AES-256.");
        return;
    }

    // Create the usable key from the byte array
    let usable_key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    // Generate a random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Initialize AES-GCM
    let cipher = Aes256Gcm::new_from_slice(usable_key).expect("Invalid key length");

    // Encrypt the data
    let ciphertext = cipher
        .encrypt(nonce, file_data.as_ref())
        .expect("Encryption failure!");

    // Write the encrypted data back to the file, including the marker
    let mut output_file = fs::File::create(file_path).expect("Error creating file");
    output_file
        .write_all(ENCRYPTION_MARKER)
        .expect("Error writing marker");
    output_file
        .write_all(&nonce_bytes)
        .expect("Error writing nonce");
    output_file
        .write_all(&ciphertext)
        .expect("Error writing ciphertext");

    println!("File encrypted successfully: {:?}", file_path);
}

// Recursively encrypt all files in a folder
pub fn encrypt_folder(folder_path: &Path, key: &str) {
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
        return;
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

    // Open the encrypted file
    let mut file = fs::File::open(file_path).expect("Error opening file");

    // Get the file size
    let file_size = file.metadata().expect("Error getting file metadata").len();

    // Check if the file size is too small to be encrypted (less than marker + nonce size)
    if file_size < (ENCRYPTION_MARKER.len() as u64 + 12) {
        println!("File is too small to be encrypted. Skipping decryption.");
        return;
    }

    // Read and check the marker
    let mut marker = [0u8; 7]; // "ENCFILE" is 7 bytes
    if let Err(_) = file.read_exact(&mut marker) {
        println!("Error reading marker: File may be incomplete or corrupted.");
        return;
    }

    if &marker != ENCRYPTION_MARKER {
        println!("File is not encrypted or marker is missing.");
        return;
    }

    // Read the nonce
    let mut nonce_bytes = [0u8; 12];
    if let Err(_) = file.read_exact(&mut nonce_bytes) {
        println!("Error reading nonce: File may be incomplete or corrupted.");
        return;
    }

    // Read the ciphertext
    let mut ciphertext = Vec::new();
    if let Err(_) = file.read_to_end(&mut ciphertext) {
        println!("Error reading ciphertext: File may be incomplete or corrupted.");
        return;
    }

    // Initialize AES-GCM
    let cipher = Aes256Gcm::new_from_slice(usable_key).expect("Invalid key length");

    // Decrypt the data
    match cipher.decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref()) {
        Ok(decrypted_data) => {
            // Write the decrypted data back to the file
            let mut output_file = fs::File::create(file_path).expect("Error creating file");
            output_file
                .write_all(&decrypted_data)
                .expect("Error writing decrypted data");
            println!("File decrypted successfully.");
        }
        Err(_) => {
            println!("Decryption failure: Possibly incorrect key or corrupted file.");
        }
    }
}

// Recursively decrypt all files in a folder
pub fn decrypt_folder(folder_path: &Path, key: &str) {
    for entry in fs::read_dir(folder_path).expect("Error reading directory") {
        let entry = entry.expect("Error getting entry");
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
