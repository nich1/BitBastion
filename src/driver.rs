use crate::pwdmanager;
use std::io;

pub fn ft_or_pwd(key: &str) {
    loop {
        println!("[0] File Tree");
        println!("[1] Password Manager");
        println!("[2] Exit");

        let mut input = String::new();

        if let Err(success) = io::stdin().read_line(&mut input) {
            println!("Error retrieving input");
            return;
        }

        if input.trim() == "0" {
            filetree_driver(key);
        }
        if input.trim() == "1" {
            pwdmanager_driver(key);
        }
        if input.trim() == "2" {
            return;
        }
    }
}

fn pwdmanager_driver(key: &str) {
    loop {
        println!("[0] List Services");
        println!("[1] Create Service ");
        println!("[2] Rename Service");
        println!("[3] Delete Service");
        println!("[4] Create Key Value Pair ");
        println!("[5] Rename Pair Key ");
        println!("[6] Update Pair Value ");
        println!("[7] Delete Key ");
        println!("[8] <- Back ");

        let mut input = String::new();

        if let Err(success) = io::stdin().read_line(&mut input) {
            println!("Error retrieving input");
            return;
        }

        if input.trim() == "0" {
            pwdmanager::read_service(key);
        }
        if input.trim() == "1" {
            let mut input2 = String::new();
            println!("Enter name of service:");

            if let Err(success) = io::stdin().read_line(&mut input2) {
                println!("Error retrieving input");
                return;
            }

            pwdmanager::create_service(key, input2.trim());
        }
        if input.trim() == "2" {
            let mut input2 = String::new();
            let mut input3 = String::new();

            println!("Enter name of service to rename:");

            if let Err(success) = io::stdin().read_line(&mut input2) {
                println!("Error retrieving input");
                return;
            }

            println!("Enter the new name for {}:", input2.trim());

            if let Err(success) = io::stdin().read_line(&mut input3) {
                println!("Error retrieving input");
                return;
            }

            pwdmanager::rename_service(key, input2.trim(), input3.trim());
        }
        if input.trim() == "3" {
            let mut input2 = String::new();
            println!("Enter name of service to DELETE:");

            if let Err(success) = io::stdin().read_line(&mut input2) {
                println!("Error retrieving input");
                return;
            }

            pwdmanager::delete_service(key, input2.trim());
        }
        if input.trim() == "4" {
            let mut input2 = String::new();
            let mut input3 = String::new();
            let mut input4 = String::new();

            println!("Enter name of service to add a key value to:");

            if let Err(success) = io::stdin().read_line(&mut input2) {
                println!("Error retrieving input");
                return;
            }

            println!("Enter key name for {}:", input2.trim());

            if let Err(success) = io::stdin().read_line(&mut input3) {
                println!("Error retrieving input");
                return;
            }

            println!("Enter value for key {}:", input3.trim());

            if let Err(success) = io::stdin().read_line(&mut input4) {
                println!("Error retrieving input");
                return;
            }

            pwdmanager::create_pair(key, input2.trim(), input3.trim(), input4.trim());
        }
        if input.trim() == "5" {
            let mut input2 = String::new();
            let mut input3 = String::new();
            let mut input4 = String::new();

            println!("Enter name of service with the key:");

            if let Err(success) = io::stdin().read_line(&mut input2) {
                println!("Error retrieving input");
                return;
            }

            println!("Enter name of key you want to rename");

            if let Err(success) = io::stdin().read_line(&mut input3) {
                println!("Error retrieving input");
                return;
            }

            println!("Enter new name for key:");

            if let Err(success) = io::stdin().read_line(&mut input4) {
                println!("Error retrieving input");
                return;
            }
            pwdmanager::rename_pair_key(key, input2.trim(), input3.trim(), input4.trim());
        }
        if input.trim() == "6" {
            let mut input2 = String::new();
            let mut input3 = String::new();
            let mut input4 = String::new();

            println!("Enter name of service with the key/value pair:");

            if let Err(success) = io::stdin().read_line(&mut input2) {
                println!("Error retrieving input");
                return;
            }

            println!("Enter name of key you want to change the value for:");

            if let Err(success) = io::stdin().read_line(&mut input3) {
                println!("Error retrieving input");
                return;
            }

            println!("Enter new value for key {}:", input3.trim());

            if let Err(success) = io::stdin().read_line(&mut input4) {
                println!("Error retrieving input");
                return;
            }
            pwdmanager::change_value(key, input2.trim(), input3.trim(), input4.trim());
        }
        if input.trim() == "7" {
            let mut input2 = String::new();
            let mut input3 = String::new();

            println!("Enter name of service:");

            if let Err(success) = io::stdin().read_line(&mut input2) {
                println!("Error retrieving input");
                return;
            }

            println!("Enter key name of the key/value pair you want to DELETE:");

            if let Err(success) = io::stdin().read_line(&mut input3) {
                println!("Error retrieving input");
                return;
            }

            pwdmanager::delete_pair(key, input2.trim(), input3.trim());
        }
        if input.trim() == "8" {
            return;
        }
    }
}

fn filee_driver(key: &str) {
    loop {
        println!("[0] Print Full Tree");

        println!("[1] Encrypt Full Tree");
        println!("[2] Encrypt File In Tree");
        println!("[3] Decrypt Full Tree");
        println!("[4] Decrypt File In Tree");

        println!("[5] Move File Into Tree");
        println!("[6] Move File Out Of Tree");
        println!("[7] Permanently Delete File In Tree");
        println!("[8] Move File Within Tree");
        println!("[9] Create Directory");
        println!("[10] Delete Directory");
        println!("[11] Rename File / Folder");

        println!("[12] <- Back ");
        if input.trim() == "0" {
            let mut input2 = String::new();
            let mut input3 = String::new();
            let mut input4 = String::new();

            println!("Enter name of service to add a key value to:");

            if let Err(success) = io::stdin().read_line(&mut input2) {
                println!("Error retrieving input");
                return;
            }

            println!("Enter key name for {}:", input2.trim());

            if let Err(success) = io::stdin().read_line(&mut input3) {
                println!("Error retrieving input");
                return;
            }

            println!("Enter value for key {}:", input3.trim());

            if let Err(success) = io::stdin().read_line(&mut input4) {
                println!("Error retrieving input");
                return;
            }

            pwdmanager::create_pair(key, input2.trim(), input3.trim(), input4.trim());
        }
    }
}
