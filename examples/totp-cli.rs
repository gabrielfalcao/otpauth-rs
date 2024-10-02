use base32::Alphabet::Rfc4648;
use clap::{Args, Parser, Subcommand};
use rand::Rng;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(version, about = "Example TOTP Cli utility for the `otpauth' crate")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}
#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    #[command(about = "Generates base32 secret")]
    Generate(Generate),
    #[command(about = "Generates TOTP token based on given base32 secret")]
    Now(Now),
}

#[derive(Args, Debug, Clone)]
pub struct Generate {
    #[arg(short, long)]
    secret: Option<String>,

    #[arg(short, long)]
    min_bytes: Option<usize>,
}

impl Generate {
    pub fn min_bytes(&self) -> usize {
        match self.min_bytes {
            Some(min_bytes) => min_bytes,
            None => {
                let mut rng = rand::thread_rng();
                let min_bytes: u8 = rng.gen();
                min_bytes.into()
            }
        }
    }
    pub fn secret(&self) -> String {
        match &self.secret {
            Some(secret) => bytes_to_base32(secret.as_bytes()),
            None => random_base32_bytes(self.min_bytes()),
        }
        .to_string()
    }
}

#[derive(Args, Debug, Clone)]
pub struct Now {
    #[arg(short, long)]
    secret: Option<String>,

    #[arg(short, long, default_value = "16")]
    stdin_read_count: usize,

    #[arg(short, long, default_value = "30")]
    valid_for_seconds: u64,
}

impl Now {
    pub fn secret(&self) -> String {
        match &self.secret {
            Some(secret) => secret.to_string(),
            None => {
                let mut buffer = Vec::<u8>::with_capacity(self.stdin_read_count);
                std::io::stdin()
                    .read(&mut buffer)
                    .expect(&format!("read {} bytes from stdin", self.stdin_read_count));
                bytes_to_base32(&buffer)
            }
        }
    }
    pub fn now(&self) -> String {
        let totp = otpauth::TOTP::from_base32(self.secret()).expect("valid base32");
        totp.generate(
            self.valid_for_seconds,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .to_string()
    }
}

fn main() {
    use Commands::*;
    println!(
        "{}",
        match Cli::parse().command {
            Generate(args) => {
                args.secret()
            }
            Now(args) => {
                args.now()
            }
        }
    );
}

pub fn bytes_to_base32(data: &[u8]) -> String {
    let data = String::from_utf8(data.to_vec()).expect("invalid string");
    match base32::decode(Rfc4648 { padding: false }, &data) {
        Some(_) => data,
        None => base32::encode(Rfc4648 { padding: false }, data.as_bytes()),
    }
}

pub fn random_base32_bytes(len: usize) -> String {
    let mut rng = rand::thread_rng();
    let mut data = Vec::with_capacity(len);
    for _ in 0..len {
        data.push(rng.gen::<u8>());
    }
    base32::encode(Rfc4648 { padding: false }, &data)
}
