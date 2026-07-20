use crate::jail::Jail;
pub mod jail;
use std::fs::{File, create_dir_all};
use std::io::{self, Read, Write};
use std::path::Path;
use std::process;

fn main() {
    let mut username = String::new();
    loop {
        print!("Enter your username: ");
        let _ = io::stdout().flush();
        let _ = io::stdin().read_line(&mut username);
        username = username.trim().into();
        if !username.chars().any(|c| ".\\/\"';,.` ".contains(c)) {
            break;
        }
    }

    // `vault` is the reserved flag-holder account. Its flag is planted out-of-band
    // (written straight to jails/vault/flag, never via a service login — see the
    // flag-handler), so NO legitimate client ever logs in as vault. Because the
    // login flow below auto-registers an unknown username with whatever password
    // the caller typed, allowing `vault` would let the first connection claim the
    // account and `type flag` directly, skipping the intended mklink/copy
    // jail-escape (issue #50). Refuse it outright; the intended attack is to break
    // OUT of some other user's jail into jails/vault, not to become vault.
    if username == "vault" {
        println!("Access denied.");
        process::exit(1);
    }

    let base = format!("./jails/{username}");
    let base_password = format!("./passwords");

    let mut password = String::new();
    let base_path = Path::new(&base);
    let base_path_password = Path::new(&base_password);
    print!("Enter your password: ");
    let _ = io::stdout().flush();
    let _ = io::stdin().read_line(&mut password);
    let password = password.trim();
    if !base_path.exists() {
        create_dir_all(base_path).expect("Could not create user directory");
    }
    if !base_path_password.exists() {
        create_dir_all(base_path_password).expect("Could not create password directory");
    }

    let passwordfile = format!("{base_password}/.{username}");
    let passwordfile_path = Path::new(&passwordfile);
    if !passwordfile_path.exists() {
        let mut passwordfile =
            File::create_new(passwordfile_path).expect("Could not create password file");
        let _ = passwordfile.write_all(password.as_bytes());
    } else {
        let mut saved_pass = String::new();
        let mut passwordfile =
            File::open(passwordfile_path).expect("Could not open .password file");
        passwordfile
            .read_to_string(&mut saved_pass)
            .expect("Could not read .password file");
        if saved_pass != password {
            println!("Wrong password!");
            process::exit(1);
        }
    }
    let mut myjail = Jail::new(&username);
    myjail.start();
}
