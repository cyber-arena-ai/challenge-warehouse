use lazy_static::lazy_static;
use std::env::current_dir;
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::symlink;
use std::{collections::HashMap, path::Path, process};

use std::path::{Component, PathBuf};

type HandlerFunction = fn(&Command, &mut HashMap<String, String>);
type Env = HashMap<String, String>;
lazy_static! {
    static ref COMMANDS: HashMap<&'static str, HandlerFunction> = HashMap::from([
        ("set", Command::handle_set as HandlerFunction),
        ("exit", Command::handle_exit as HandlerFunction),
        ("cd", Command::handle_cd as HandlerFunction),
        ("dir", Command::handle_dir as HandlerFunction),
        ("help", Command::handle_help as HandlerFunction),
        ("type", Command::handle_type as HandlerFunction),
        ("whoami", Command::handle_whoami as HandlerFunction),
        ("del", Command::handle_del as HandlerFunction),
        ("copy", Command::handle_copy as HandlerFunction),
        ("mklink", Command::handle_mklink as HandlerFunction),
        ("mkdir", Command::handle_mkdir as HandlerFunction),
        ("echo", Command::handle_echo as HandlerFunction),
        ("call", Command::handle_call as HandlerFunction)
    ]);
}

#[derive(Debug)]
pub struct Command {
    tokens: Vec<Token>,
    base_dir: String,
}

#[derive(Debug)]
struct Token {
    value: String,
}

impl Command {
    pub fn handle_command(&self, env: &mut Env) {
        let entered_command = self
            .tokens
            .first()
            .unwrap() // Commands need at least the first token to be here
            .value
            .as_str();
        match COMMANDS.get(entered_command) {
            Some(command) => command(self, env),
            None => println!(
                "'{entered_command}' is not recognized as an internal or external command, operable program or batch file."
            ),
        }
    }

    fn handle_set(&self, env: &mut Env) {
        if self.tokens.len() == 1 {
            print_env(env);
            return;
        }
        let pair = self.tokens.get(1).unwrap().value.split_once("=");
        match pair {
            Some((key, value)) if !key.is_empty() && !value.is_empty() => {
                env.insert(key.to_string(), value.to_string());
            }
            Some((key, value)) if !key.is_empty() && value.is_empty() => {
                env.remove(key);
            }
            None => {
                let key = &self.tokens.get(1).unwrap().value;
                if env.contains_key(key) {
                    let (key, value) = env.get_key_value(key).unwrap();
                    println!("{key}={value}");
                } else {
                    println!("Environment variable {key} not defined");
                }
            }
            _ => {
                println!("The syntax of the command is incorrect.")
            }
        }
    }

    fn handle_exit(&self, _: &mut Env) {
        process::exit(0);
    }

    fn handle_cd(&self, env: &mut Env) {
        let cwd = match env.get("CWD") {
            Some(p) => p,
            None => {
                env.insert("CWD".to_string(), "/".to_string());
                "/"
            }
        };
        if self.tokens.len() == 1 {
            println!("C:{cwd}");
            return;
        }
        let cwd = if !cwd.ends_with("/") {
            &format!("{cwd}/")
        } else {
            cwd
        };
        let path = &self.tokens.get(1).unwrap().value;
        let base_dir = &self.base_dir;
        let relative_path = if path.starts_with("/") {
            path.to_string()
        } else {
            format!("{cwd}{path}")
        };
        let relative_path = normalize_path_string(&relative_path);
        let full_path = format!("{base_dir}{relative_path}");
        if Path::new(&full_path).is_dir() {
            env.insert("CWD".to_string(), relative_path);
        } else {
            println!("The system cannot find the path specified.")
        }
    }

    fn handle_dir(&self, env: &mut Env) {
        let cwd = match env.get("CWD") {
            Some(p) => p,
            None => {
                env.insert("CWD".to_string(), "/".to_string());
                "/"
            }
        };
        if self.tokens.len() == 1 {
            let base_dir = &self.base_dir;
            let full_path = format!("{base_dir}{cwd}");
            let path = Path::new(&full_path);
            let entries = match path.read_dir() {
                Ok(entries) => entries,
                Err(_) => {
                    println!("The system cannot find the path specified.");
                    env.insert("CWD".to_string(), "/".to_string());
                    return;
                }
            }
            .flatten();
            for entry in entries {
                let node = entry
                    .file_name()
                    .into_string()
                    .expect("Could not convert node to string!");
                if node.starts_with('.') {
                    continue;
                }
                println!("{node}")
            }
        } else {
            todo!("Can't list specific path");
        }
    }

    fn handle_help(&self, _: &mut Env) {
        for command in COMMANDS.keys() {
            println!("{command}")
        }
    }

    fn handle_type(&self, env: &mut Env) {
        match self.tokens.as_slice() {
            [_] => {
                println!("The syntax of the command is incorrect.");
            }
            [_, file, ..] => {
                let cwd = env
                    .entry("CWD".to_string())
                    .or_insert_with(|| "/".to_string());

                let cwd = add_slash_to_path(cwd);

                let path = &file.value;
                let base_dir = &self.base_dir;
                let relative_path = normalize_path_string(&format!("{cwd}{path}"));
                let full_path = format!("{base_dir}{relative_path}");

                if !Path::new(&full_path).is_file() {
                    println!("The system cannot find the file specified.");
                    return;
                }

                let content = match fs::read_to_string(full_path) {
                    Ok(content) => content,
                    Err(_) => {
                        println!("Could not retrieve content of file.");
                        return;
                    }
                };
                println!("{content}");
            }
            _ => process::exit(1),
        }
    }

    fn handle_whoami(&self, env: &mut Env) {
        if let [_, invalid_token, ..] = self.tokens.as_slice() {
            println!(
                "ERROR: Invalid argument/option - '{}'.",
                invalid_token.value
            );
            return;
        }

        let username = match env.get("USERNAME") {
            Some(username) => username,
            None => {
                let username = self.base_dir.split("/").last().unwrap();
                env.insert("USERNAME".to_string(), username.to_string());
                username
            }
        };
        println!("{username}");
    }

    fn handle_del(&self, env: &mut Env) {
        match self.tokens.as_slice() {
            [_] => {
                println!("The syntax of the command is incorrect.");
            }
            [_, file, ..] => {
                let cwd = env
                    .entry("CWD".to_string())
                    .or_insert_with(|| "/".to_string());

                let cwd = add_slash_to_path(cwd);

                let filename = &file.value;
                let base_dir = &self.base_dir;
                let relative_path = normalize_path_string(&filename.to_string());
                let full_path = format!("{base_dir}{cwd}{relative_path}");


                if !Path::new(&full_path).is_file() {
                    println!("The system cannot find the file specified.");
                    return;
                }

                if Path::new(&full_path).is_dir() {
                    println!("This system command cannot delete directories.");
                    return;
                }


                let _ = fs::remove_file(full_path);
            }
            _ => process::exit(1),
        }
    }

    fn handle_mkdir(&self, env: &mut Env) {
        match self.tokens.as_slice() {
            [_] => {
                println!("The syntax of the command is incorrect.");
            }
            [_, dir, ..] => {
                let cwd = env
                    .entry("CWD".to_string())
                    .or_insert_with(|| "/".to_string());

                let cwd = add_slash_to_path(cwd);

                let dirname = &dir.value;
                let base_dir = &self.base_dir;
                let relative_path = normalize_path_string(&format!("{cwd}{dirname}"));
                let full_path = format!("{base_dir}{relative_path}");


                let _ = fs::create_dir(full_path);
            }
            _ => process::exit(1),
        }
    }

    fn handle_mklink(&self, env: &mut Env) {
        match self.tokens.as_slice() {
            [_] => {
                println!("The syntax of the command is incorrect.");
            }
            [_, from, to, ..] => {
                let cwd = env
                    .entry("CWD".to_string())
                    .or_insert_with(|| "/".to_string());

                let cwd = add_slash_to_path(cwd);

                let dirname = &from.value;
                let base_dir = &self.base_dir;
                let cwd = normalize_path_string(&cwd.to_string());
                let from_path = format!("{base_dir}{cwd}/{dirname}");

                let dirname = &to.value;
                let base_dir = &self.base_dir;
                let cwd = normalize_path_string(&cwd.to_string());
                let to_path = format!("{base_dir}{cwd}/{dirname}");

                if Path::new(&from_path).is_dir() {
                    println!("This system command cannot link to directories.");
                    return;
                }

                let _ = symlink(from_path, to_path);
            }
            _ => process::exit(1),
        }
    }

    fn handle_copy(&self, env: &mut Env) {
        match self.tokens.as_slice() {
            [_] => {
                println!("The syntax of the command is incorrect.");
            }
            [_, from, to, ..] => {
                let cwd = env
                    .entry("CWD".to_string())
                    .or_insert_with(|| "/".to_string());


                let cwd = add_slash_to_path(cwd);
                let dirname = &from.value;
                let base_dir = &self.base_dir;
                let cwd = normalize_path_string(&cwd.to_string());
                let from_path = format!("{base_dir}{cwd}/{dirname}");

                if !Path::new(&from_path).is_file() {
                    println!("The system cannot find the file specified.");
                    return;
                }

                let dirname = &to.value;
                let base_dir = &self.base_dir;
                let cwd = normalize_path_string(&cwd.to_string());
                let to_path = format!("{base_dir}{cwd}/{dirname}");

                let _ = fs::copy(from_path, to_path);
            }
            _ => process::exit(1),
        }
    }

    fn handle_echo(&self, env: &mut Env) {
        match self.tokens.as_slice() {
            [_] => {
                println!("The syntax of the command is incorrect.");
            }
            [_, _, ..] => {
                let mut output = String::new();
                let mut to_file = false;
                let mut filename = "";
                let tokens = self.tokens.iter();
                for token in tokens.skip(1) {
                    if to_file {
                        filename = &token.value;
                        break;
                    }

                    if token.value == ">" {
                        to_file = true;
                        continue;
                    }
                    output.push(' ');
                    output.push_str(&token.value);
                }

                let output = output.replace("\\n", "\n");
                let output = output.replace("\\t", "\t");
                let output = output.replace("\\r", "\r");
                let output = output.replace("\\\\", "\\");
                let output = output.trim();
                let trim_quote = |c| c == '\'' || c == '"';
                let output= output.lines()
                    .map(|line| line.trim_matches(trim_quote))
                    .collect::<Vec<&str>>()
                    .join("\n");
                if !to_file {
                    println!("{output}");
                    return;
                }

                if filename.is_empty() {
                    println!("The syntax of the command is incorrect.");
                    return;
                }
                let cwd = env
                    .entry("CWD".to_string())
                    .or_insert_with(|| "/".to_string());

                let cwd = add_slash_to_path(cwd);
                let base_dir = &self.base_dir;
                let relative_path = normalize_path_string(&format!("{cwd}{filename}"));
                let to_path = format!("{base_dir}{relative_path}");


                let _ = fs::write(to_path, output.as_bytes());
            }
            _ => process::exit(1),
        }
    }

    fn handle_call(&self, env: &mut Env) {
        match self.tokens.as_slice() {
            [_] => {
                println!("The syntax of the command is incorrect.");
            }
            [_, file, ..] => {
                let cwd = env
                    .entry("CWD".to_string())
                    .or_insert_with(|| "/".to_string());

                let cwd = add_slash_to_path(cwd);

                let filename = &file.value;
                let base_dir = &self.base_dir;
                let relative_path = normalize_path_string(&filename.to_string());
                let full_path = format!("{base_dir}{cwd}{relative_path}");


                if !Path::new(&full_path).is_file() {
                    println!("The system cannot find the file specified.");
                    return;
                }

                if Path::new(&full_path).is_dir() {
                    println!("This system command cannot call directories.");
                    return;
                }

                let content = match fs::read_to_string(full_path) {
                    Ok(content) => content,
                    Err(_) => {
                        println!("Could not retrieve content of file.");
                        return;
                    }
                };
                let binding = current_dir().expect("Can not get current working directory!");
                let basedir = binding.to_string_lossy();
                let basedir = format!("{}/{}", basedir, "jails");
                let username = match env.get("USERNAME") {
                    Some(username) => username,
                    None => process::exit(0),
                }
                .clone();
                let userdir = format!("{basedir}/{username}");
                for line in content.lines() {
                    if !Path::new(&userdir).exists() {
                        println!("Tampering detected. Quitting!");
                        process::exit(0);
                    }
                    let command = Command::try_from((line.into(), format!("{basedir}/{username}")));
                        match command {
                            Ok(command) => command.handle_command(env),
                            Err(s) => println!("{s}"),
                        }
                }
            }
            _ => process::exit(1),
        }
    }
}

impl TryFrom<(String, String)> for Command {
    type Error = &'static str;
    fn try_from(value: (String, String)) -> Result<Self, Self::Error> {
        let tokens = parse_command(value.0)?;
        Ok(Command {
            tokens,
            base_dir: value.1,
        })
    }
}

fn add_slash_to_path(cwd: &mut String) -> &String {
    if !cwd.ends_with("/") {
        cwd.push('/');
    }
    cwd
}


fn normalize_path_string(path: &str) -> String {
    let mut result = PathBuf::from("/");
    for component in Path::new(path).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            Component::Normal(c) => result.push(c),
            _ => {}
        }
    }

    result.to_string_lossy().into_owned()
}

fn parse_command(command: String) -> Result<Vec<Token>, &'static str> {
    let mut parsed_tokens = Vec::new();

    if !command.contains(" ") {
        parsed_tokens.push(Token { value: command });
        return Ok(parsed_tokens);
    }

    let tokens: Vec<&str> = command.split(" ").collect();
    let mut long_token = Vec::new();
    let mut tick = "";
    let mut in_quotes = false;
    for token in tokens {
        if token.is_empty() {
            continue;
        }
        if (token.contains('\'') || token.contains('"')) && !in_quotes {
            let index = match (token.find('\''), token.find('"')) {
                (None, Some(j)) => j,
                (Some(i), None) => i,
                (Some(i), Some(j)) => i.min(j),
                (None, None) => unreachable!(),
            };
            in_quotes = true;
            tick = &token[index..index + 1];
            long_token.push(token);
        } else if token.ends_with(tick) && in_quotes {
            in_quotes = false;
            long_token.push(token);
            parsed_tokens.push(Token {
                value: long_token.clone().join(" "),
            });
            long_token.clear();
        } else if in_quotes {
            long_token.push(token);
        } else {
            parsed_tokens.push(Token {
                value: token.to_string(),
            });
        }
    }
    if in_quotes {
        return Err("Error: No closing tick found");
    }

    return Ok(parsed_tokens);
}

fn print_env(env: &Env) {
    for (k, v) in env {
        println!("{k}={v}");
    }
}
