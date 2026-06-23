mod command;

use crate::jail::command::Command;
use rustyline::{Editor, history::FileHistory};
use std::{collections::HashMap, env::current_dir, path::Path, process};

pub struct Jail {
    env: HashMap<String, String>,
    linereader: Editor<(), FileHistory>,
}

impl Jail {
    pub fn new(name: &str) -> Self {
        let linereader = Editor::new().expect("Could not create line reader");
        let mut env = HashMap::new();
        env.insert("CWD".to_string(), "/".to_string());
        env.insert("USERNAME".to_string(), name.to_string());
        Jail { env, linereader }
    }

    pub fn start(&mut self) {
        let binding = current_dir().expect("Can not get current working directory!");
        let basedir = binding.to_string_lossy();
        let basedir = format!("{}/{}", basedir, "jails");
        let username = match self.env.get("USERNAME") {
            Some(username) => username,
            None => process::exit(0),
        }
        .clone();
        let userdir = format!("{basedir}/{username}");
        println!("saarCTF 2025 presents: RCE as a Service");
        loop {
            if !Path::new(&userdir).exists() {
                println!("Tampering detected. Quitting!");
                process::exit(0);
            }
            let input = self.prompt();
            if input.is_empty() {
                continue;
            }
            let command = Command::try_from((input, format!("{basedir}/{username}")));
            match command {
                Ok(command) => command.handle_command(&mut self.env),
                Err(s) => println!("{s}"),
            }
        }
    }

    fn prompt(&mut self) -> String {
        let cwd = self.env.entry("CWD".into()).or_insert("/".into());
        let path = format!("C:{cwd}> ");
        loop {
            let readline = self.linereader.readline(&path);
            match readline {
                Ok(line) => {
                    let _ = self.linereader.add_history_entry(line.as_str());
                    return line;
                }
                Err(rustyline::error::ReadlineError::Interrupted) => process::exit(0),
                // Client disconnected (socket EOF). Under socat the wrapper
                // killed us; under the inetd wrapper we must exit ourselves,
                // else readline returns Eof forever and the process busy-spins
                // at 100% CPU after every closed connection.
                Err(rustyline::error::ReadlineError::Eof) => process::exit(0),
                Err(_) => continue,
            }
        }
    }
}
