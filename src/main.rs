use std::env;
use std::io;
use std::path::Path;
mod driver;
mod filetree;
mod keymanager;
mod pwdmanager;

fn main() {
    d();
    //pwdmanager::create_service("test", "ms");

    //pwdmanager::read_service("test");
}

fn d() {
    // Check if key file exists
    if keymanager::is_key_created() {
        // Get password
        println!("Key:");
        let mut key = String::new();
        if let Err(success) = io::stdin().read_line(&mut key) {
            println!("Error retrieving input");
            return;
        }
        let trimmedkey = key.trim();
        driver::ft_or_pwd(trimmedkey);
    } else {
        // If not, create key process
        println!("Your master key will be hashed and used to encrypt the file tree");
        println!("You can not change your Master Key after you set it");
        println!(
            "Forgetting the master key will make you incapable of accessing the application\n"
        );
        println!("Leading and trailing whitespace will be removed");

        println!("Enter Master Key:");
        let mut key = String::new();
        if let Err(success) = io::stdin().read_line(&mut key) {
            println!("Error retrieving input");
            return;
        }
        let trimmedkey = key.trim();
        keymanager::enter_key(trimmedkey);
    }
}
