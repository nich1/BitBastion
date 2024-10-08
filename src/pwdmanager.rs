use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::keymanager;

#[derive(Debug, Deserialize, Serialize)]
struct ServiceData {
    Title: String,
    Pairs: Vec<KeyValuePair>,
}

#[derive(Debug, Deserialize, Serialize)]
struct KeyValuePair {
    Key: String,
    Value: String,
}

fn is_dat_empty() -> bool {
    let path = Path::new("Managed/dat.enc");
    match fs::metadata(&path) {
        Ok(metadata) => {
            if metadata.is_file() {
                if metadata.len() == 0 {
                    return true;
                } else {
                    return false;
                    println!("Data is empty");
                }
            } else {
                println!("This is not a regular file");
            }
        }
        Err(e) => {
            println!("ERR");
            return true;
        }
    }
    println!("ERR");

    return true;
}

pub fn change_value(key: &str, service_name: &str, pair_key: &str, new_value: &str) {
    // Validate key
    if !keymanager::check_key(key) {
        println!("Invalid key");
        return;
    }

    if is_dat_empty() {
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

    // Create the AES-GCM cipher
    let cipher = Aes256Gcm::new(usable_key);

    // Read the file content (nonce + ciphertext)
    let file_content = fs::read("Managed/dat.enc").expect("Error reading encrypted file");

    // Split the file content into nonce and ciphertext
    let (nonce_bytes, ciphertext) = file_content.split_at(12); // First 12 bytes are the nonce

    // Use the nonce for decryption
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt the ciphertext
    let decrypted_data = match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => plaintext,
        Err(_) => {
            println!("Decryption failed");
            return;
        }
    };

    // Convert the decrypted bytes back into a JSON string
    let decrypted_json = String::from_utf8(decrypted_data).expect("Failed to decode UTF-8");

    // Deserialize the JSON string into the original struct
    let mut service_data: Vec<ServiceData> =
        serde_json::from_str(&decrypted_json).expect("Error deserializing JSON");

    // Search for service
    let mut found: bool = false;
    'mainloop: for service in &mut service_data {
        if service.Title == service_name {
            if service.Pairs.len() > 0 {
                let mut count = 0;
                for mut pair in &mut service.Pairs {
                    if pair.Key == pair_key {
                        pair.Value = new_value.to_string();
                        break 'mainloop;
                    }
                }
            }
        }
    }

    // Serialize the updated list of services to JSON
    let updated_json = serde_json::to_string_pretty(&service_data).expect("Error serializing");

    // Generate a random nonce (12 bytes) for encryption
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the updated JSON data
    let ciphertext = cipher
        .encrypt(nonce, updated_json.as_ref())
        .expect("Encryption failure!");

    // Prepend the nonce to the ciphertext before writing to the file
    let mut file_data = Vec::new();
    file_data.extend_from_slice(&nonce_bytes); // 12-byte nonce
    file_data.extend_from_slice(&ciphertext); // Encrypted data

    // Write the nonce + ciphertext to the file
    fs::write("Managed/dat.enc", file_data).expect("Error writing file");
}

pub fn rename_pair_key(key: &str, service_name: &str, pair_key: &str, new_pair_key: &str) {
    // Validate key
    if !keymanager::check_key(key) {
        println!("Invalid key");
        return;
    }

    if is_dat_empty() {
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

    // Create the AES-GCM cipher
    let cipher = Aes256Gcm::new(usable_key);

    // Read the file content (nonce + ciphertext)
    let file_content = fs::read("Managed/dat.enc").expect("Error reading encrypted file");

    // Split the file content into nonce and ciphertext
    let (nonce_bytes, ciphertext) = file_content.split_at(12); // First 12 bytes are the nonce

    // Use the nonce for decryption
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt the ciphertext
    let decrypted_data = match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => plaintext,
        Err(_) => {
            println!("Decryption failed");
            return;
        }
    };

    // Convert the decrypted bytes back into a JSON string
    let decrypted_json = String::from_utf8(decrypted_data).expect("Failed to decode UTF-8");

    // Deserialize the JSON string into the original struct
    let mut service_data: Vec<ServiceData> =
        serde_json::from_str(&decrypted_json).expect("Error deserializing JSON");

    // Search for service
    let mut found: bool = false;
    'mainloop: for service in &mut service_data {
        if service.Title == service_name {
            if service.Pairs.len() > 0 {
                let mut count = 0;
                for mut pair in &mut service.Pairs {
                    if pair.Key == pair_key {
                        pair.Key = new_pair_key.to_string();
                        break 'mainloop;
                    }
                }
            }
        }
    }

    // Serialize the updated list of services to JSON
    let updated_json = serde_json::to_string_pretty(&service_data).expect("Error serializing");

    // Generate a random nonce (12 bytes) for encryption
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the updated JSON data
    let ciphertext = cipher
        .encrypt(nonce, updated_json.as_ref())
        .expect("Encryption failure!");

    // Prepend the nonce to the ciphertext before writing to the file
    let mut file_data = Vec::new();
    file_data.extend_from_slice(&nonce_bytes); // 12-byte nonce
    file_data.extend_from_slice(&ciphertext); // Encrypted data

    // Write the nonce + ciphertext to the file
    fs::write("Managed/dat.enc", file_data).expect("Error writing file");
}

pub fn delete_pair(key: &str, service_name: &str, pair_key: &str) {
    // Validate key
    if !keymanager::check_key(key) {
        println!("Invalid key");
        return;
    }

    if is_dat_empty() {
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

    // Create the AES-GCM cipher
    let cipher = Aes256Gcm::new(usable_key);

    // Read the file content (nonce + ciphertext)
    let file_content = fs::read("Managed/dat.enc").expect("Error reading encrypted file");

    // Split the file content into nonce and ciphertext
    let (nonce_bytes, ciphertext) = file_content.split_at(12); // First 12 bytes are the nonce

    // Use the nonce for decryption
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt the ciphertext
    let decrypted_data = match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => plaintext,
        Err(_) => {
            println!("Decryption failed");
            return;
        }
    };

    // Convert the decrypted bytes back into a JSON string
    let decrypted_json = String::from_utf8(decrypted_data).expect("Failed to decode UTF-8");

    // Deserialize the JSON string into the original struct
    let mut service_data: Vec<ServiceData> =
        serde_json::from_str(&decrypted_json).expect("Error deserializing JSON");

    // Search for service
    let mut found: bool = false;
    'toploop: for service in &mut service_data {
        if service.Title == service_name {
            if service.Pairs.len() > 0 {
                let mut count = 0;
                for pair in &service.Pairs {
                    if pair.Key == pair_key {
                        found = true;
                        break;
                    }
                    count += 1;
                }
                if found {
                    service.Pairs.remove(count);
                    break 'toploop;
                }
            }
        }
    }

    // Serialize the updated list of services to JSON
    let updated_json = serde_json::to_string_pretty(&service_data).expect("Error serializing");

    // Generate a random nonce (12 bytes) for encryption
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the updated JSON data
    let ciphertext = cipher
        .encrypt(nonce, updated_json.as_ref())
        .expect("Encryption failure!");

    // Prepend the nonce to the ciphertext before writing to the file
    let mut file_data = Vec::new();
    file_data.extend_from_slice(&nonce_bytes); // 12-byte nonce
    file_data.extend_from_slice(&ciphertext); // Encrypted data

    // Write the nonce + ciphertext to the file
    fs::write("Managed/dat.enc", file_data).expect("Error writing file");
}

pub fn create_pair(key: &str, service_name: &str, pair_key: &str, pair_value: &str) {
    // Validate key
    if !keymanager::check_key(key) {
        println!("Invalid key");
        return;
    }

    if is_dat_empty() {
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

    // Create the AES-GCM cipher
    let cipher = Aes256Gcm::new(usable_key);

    // Read the file content (nonce + ciphertext)
    let file_content = fs::read("Managed/dat.enc").expect("Error reading encrypted file");

    // Split the file content into nonce and ciphertext
    let (nonce_bytes, ciphertext) = file_content.split_at(12); // First 12 bytes are the nonce

    // Use the nonce for decryption
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt the ciphertext
    let decrypted_data = match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => plaintext,
        Err(_) => {
            println!("Decryption failed");
            return;
        }
    };

    // Convert the decrypted bytes back into a JSON string
    let decrypted_json = String::from_utf8(decrypted_data).expect("Failed to decode UTF-8");

    // Deserialize the JSON string into the original struct
    let mut service_data: Vec<ServiceData> =
        serde_json::from_str(&decrypted_json).expect("Error deserializing JSON");

    // Search for service
    for service in &mut service_data {
        if service.Title == service_name {
            if service.Pairs.len() > 0 {
                for pair in &service.Pairs {
                    if pair.Key == pair_key {
                        println!(
                            "A key pair already exists. You can update the current one if you wish"
                        );
                        return;
                    }
                }
            }
            // Create and push key value pair
            let added_pair: KeyValuePair = KeyValuePair {
                Key: pair_key.to_string(),
                Value: pair_value.to_string(),
            };
            service.Pairs.push(added_pair);
        }
    }

    // Serialize the updated list of services to JSON
    let updated_json = serde_json::to_string_pretty(&service_data).expect("Error serializing");

    // Generate a random nonce (12 bytes) for encryption
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the updated JSON data
    let ciphertext = cipher
        .encrypt(nonce, updated_json.as_ref())
        .expect("Encryption failure!");

    // Prepend the nonce to the ciphertext before writing to the file
    let mut file_data = Vec::new();
    file_data.extend_from_slice(&nonce_bytes); // 12-byte nonce
    file_data.extend_from_slice(&ciphertext); // Encrypted data

    // Write the nonce + ciphertext to the file
    fs::write("Managed/dat.enc", file_data).expect("Error writing file");
}

pub fn delete_service(key: &str, service_name: &str) {
    // Validate key
    if !keymanager::check_key(key) {
        println!("Invalid key");
        return;
    }

    if is_dat_empty() {
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

    // Create the AES-GCM cipher
    let cipher = Aes256Gcm::new(usable_key);

    // Read existing encrypted file (if it exists)
    let mut services: Vec<ServiceData> = match fs::read("Managed/dat.enc") {
        Ok(file_content) => {
            if file_content.is_empty() {
                // If the file is empty, initialize an empty vector
                Vec::new()
            } else {
                // Split the file content into nonce and ciphertext
                let (nonce_bytes, ciphertext) = file_content.split_at(12); // First 12 bytes are the nonce

                // Use the nonce for decryption
                let nonce = Nonce::from_slice(nonce_bytes);

                // Decrypt the ciphertext
                let decrypted_data = match cipher.decrypt(nonce, ciphertext) {
                    Ok(plaintext) => plaintext,
                    Err(_) => {
                        println!("Decryption failed.");
                        return;
                    }
                };

                // Convert the decrypted bytes back into a JSON string
                let decrypted_json =
                    String::from_utf8(decrypted_data).expect("Failed to decode UTF-8");

                // Deserialize the JSON string into a Vec<ServiceData>
                serde_json::from_str(&decrypted_json).expect("Error deserializing JSON")
            }
        }
        Err(_) => {
            // If the file doesn't exist, start with an empty vector
            Vec::new()
        }
    };

    // Change service
    let mut found: bool = false;
    let mut count = 0;
    for service in &mut services {
        if service.Title == service_name {
            found = true;
            break;
        }
        count += 1;
    }
    if found == false {
        println!("Service not found");
        return;
    }
    services.remove(count);

    // Serialize the updated list of services to JSON
    let updated_json = serde_json::to_string_pretty(&services).expect("Error serializing");

    // Generate a random nonce (12 bytes) for encryption
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the updated JSON data
    let ciphertext = cipher
        .encrypt(nonce, updated_json.as_ref())
        .expect("Encryption failure!");

    // Prepend the nonce to the ciphertext before writing to the file
    let mut file_data = Vec::new();
    file_data.extend_from_slice(&nonce_bytes); // 12-byte nonce
    file_data.extend_from_slice(&ciphertext); // Encrypted data

    // Write the nonce + ciphertext to the file
    fs::write("Managed/dat.enc", file_data).expect("Error writing file");

    println!("\tService removed successfully!");
}

pub fn rename_service(key: &str, service_name: &str, new_service_name: &str) {
    // Validate key
    if !keymanager::check_key(key) {
        println!("Invalid key");
        return;
    }

    if is_dat_empty() {
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

    // Create the AES-GCM cipher
    let cipher = Aes256Gcm::new(usable_key);

    // Read existing encrypted file (if it exists)
    let mut services: Vec<ServiceData> = match fs::read("Managed/dat.enc") {
        Ok(file_content) => {
            if file_content.is_empty() {
                // If the file is empty, initialize an empty vector
                Vec::new()
            } else {
                // Split the file content into nonce and ciphertext
                let (nonce_bytes, ciphertext) = file_content.split_at(12); // First 12 bytes are the nonce

                // Use the nonce for decryption
                let nonce = Nonce::from_slice(nonce_bytes);

                // Decrypt the ciphertext
                let decrypted_data = match cipher.decrypt(nonce, ciphertext) {
                    Ok(plaintext) => plaintext,
                    Err(_) => {
                        println!("Decryption failed.");
                        return;
                    }
                };

                // Convert the decrypted bytes back into a JSON string
                let decrypted_json =
                    String::from_utf8(decrypted_data).expect("Failed to decode UTF-8");

                // Deserialize the JSON string into a Vec<ServiceData>
                serde_json::from_str(&decrypted_json).expect("Error deserializing JSON")
            }
        }
        Err(_) => {
            // If the file doesn't exist, start with an empty vector
            Vec::new()
        }
    };

    // Change service
    let mut found: bool = false;
    for service in &mut services {
        if service.Title == service_name {
            service.Title = new_service_name.to_string();
            found = true;
        }
    }
    if found == false {
        println!("Service not found");
        return;
    }

    // Serialize the updated list of services to JSON
    let updated_json = serde_json::to_string_pretty(&services).expect("Error serializing");

    // Generate a random nonce (12 bytes) for encryption
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the updated JSON data
    let ciphertext = cipher
        .encrypt(nonce, updated_json.as_ref())
        .expect("Encryption failure!");

    // Prepend the nonce to the ciphertext before writing to the file
    let mut file_data = Vec::new();
    file_data.extend_from_slice(&nonce_bytes); // 12-byte nonce
    file_data.extend_from_slice(&ciphertext); // Encrypted data

    // Write the nonce + ciphertext to the file
    fs::write("Managed/dat.enc", file_data).expect("Error writing file");

    println!("\tService added successfully!");
}

pub fn read_service(key: &str) {
    // Validate key
    if !keymanager::check_key(key) {
        println!("Invalid key");
        return;
    }

    if is_dat_empty() {
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

    // Create the AES-GCM cipher
    let cipher = Aes256Gcm::new(usable_key);

    // Read the file content (nonce + ciphertext)
    let file_content = fs::read("Managed/dat.enc").expect("Error reading encrypted file");

    // Split the file content into nonce and ciphertext
    let (nonce_bytes, ciphertext) = file_content.split_at(12); // First 12 bytes are the nonce

    // Use the nonce for decryption
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt the ciphertext
    let decrypted_data = match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => plaintext,
        Err(_) => {
            println!("Decryption failed");
            return;
        }
    };

    // Convert the decrypted bytes back into a JSON string
    let decrypted_json = String::from_utf8(decrypted_data).expect("Failed to decode UTF-8");

    // Deserialize the JSON string into the original struct
    let service_data: Vec<ServiceData> =
        serde_json::from_str(&decrypted_json).expect("Error deserializing JSON");

    // Print the deserialized data
    for service in service_data {
        println!("Service: {}", service.Title);
        for pair in service.Pairs {
            println!("\tKey: \"{}\", Value: \"{}\"", pair.Key, pair.Value);
        }
    }
}

pub fn create_service(key: &str, service_name: &str) {
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

    // Create the AES-GCM cipher
    let cipher = Aes256Gcm::new(usable_key);

    // Read existing encrypted file (if it exists)
    let mut services: Vec<ServiceData> = match fs::read("Managed/dat.enc") {
        Ok(file_content) => {
            if file_content.is_empty() {
                // If the file is empty, initialize an empty vector
                Vec::new()
            } else {
                // Split the file content into nonce and ciphertext
                let (nonce_bytes, ciphertext) = file_content.split_at(12); // First 12 bytes are the nonce

                // Use the nonce for decryption
                let nonce = Nonce::from_slice(nonce_bytes);

                // Decrypt the ciphertext
                let decrypted_data = match cipher.decrypt(nonce, ciphertext) {
                    Ok(plaintext) => plaintext,
                    Err(_) => {
                        println!("Decryption failed.");
                        return;
                    }
                };

                // Convert the decrypted bytes back into a JSON string
                let decrypted_json =
                    String::from_utf8(decrypted_data).expect("Failed to decode UTF-8");

                // Deserialize the JSON string into a Vec<ServiceData>
                serde_json::from_str(&decrypted_json).expect("Error deserializing JSON")
            }
        }
        Err(_) => {
            // If the file doesn't exist, start with an empty vector
            Vec::new()
        }
    };

    for service in &services {
        if service.Title == service_name {
            println!("A service already exists with this name");
            return;
        }
    }

    // Add the new service to the list
    let new_service = ServiceData {
        Title: service_name.to_string(),
        Pairs: Vec::new(),
    };

    services.push(new_service);

    // Serialize the updated list of services to JSON
    let updated_json = serde_json::to_string_pretty(&services).expect("Error serializing");

    // Generate a random nonce (12 bytes) for encryption
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the updated JSON data
    let ciphertext = cipher
        .encrypt(nonce, updated_json.as_ref())
        .expect("Encryption failure!");

    // Prepend the nonce to the ciphertext before writing to the file
    let mut file_data = Vec::new();
    file_data.extend_from_slice(&nonce_bytes); // 12-byte nonce
    file_data.extend_from_slice(&ciphertext); // Encrypted data

    // Write the nonce + ciphertext to the file
    fs::write("Managed/dat.enc", file_data).expect("Error writing file");

    println!("\tService added successfully!");
}
