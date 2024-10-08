use std::io;
use std::path::Path;

mod keymanager;
mod pwdmanager;
mod filetree;

fn main() {
    let path = Path::new("Drive");
    filetree::decrypt_folder(path, "test");

}
