use std::io::{Read, Write};

use aead::{OsRng, rand_core::RngCore};
use argon2::password_hash::SaltString;
use clap::{Parser, Subcommand, ValueEnum};
use fuser::MountOption;

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as b64};
use fscryptrs::{Fs, crypto};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crypto::{
    Aes256Gcm as Aes, Blake2 as Bl2, BlockOriented as Blk, ChaCha20Poly1305 as Cha, Sha3 as Sha,
    StreamOriented as Stm,
};
use tracing_subscriber::EnvFilter;

/// Contains filesystem configuration
#[derive(Serialize, Deserialize, Debug)]
struct Config {
    /// Salt used with user password
    salt: String,
    /// Cipher used for encrypting sensitive information about the filesystem
    cipher: Cipher,
    /// Encrypted Secret Config
    data: String,
}

/// Contains encrypted data, specifically master keys for encryption file contents and encrypting
/// directory filenames
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "Crypto")]
struct SecretCfg {
    /// Master key used for file encryption
    key: crypto::Key,
    /// Key used for encrypting filenames
    #[serde(with = "serde_arrays")]
    dir_key: [u8; 64],
    /// Cipher used for file encryption
    cipher: Cipher,
    /// Digest used for file integrity checking
    digest: Digest,
    /// Mode used for file alignment
    mode: Mode,
    /// Controls the file integrity checking
    check_digest: bool,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Enables the debug output of the filesystem
    /// It is not recommended unless debugging, it may leak sensitive information
    #[arg(short, long)]
    debug: bool,
}

impl Cli {
    fn prompt_password() -> Result<String> {
        loop {
            let pw = rpassword::prompt_password("Please enter password used for encryption: ")?;
            let pw2 = rpassword::prompt_password("Retype the password: ")?;

            if pw == pw2 {
                break Ok(pw);
            }
            println!("The passwords do not match. Try again.");
        }
    }

    fn encrypt_config<A>(pw: &[u8], cipher: Cipher, cfg: SecretCfg) -> Result<Config>
    where
        A: aead::Aead + aead::KeyInit,
    {
        let salt = argon2::password_hash::SaltString::generate(OsRng);
        let mut bin_salt = [0u8; 16];
        salt.decode_b64(&mut bin_salt).expect("is a valid salt");
        debug!("bin_salt={:?}", bin_salt);
        let mut key: crypto::Key = [0u8; 32];
        let _ = argon2::Argon2::default().hash_password_into(pw, &bin_salt, &mut key);

        let data = toml::to_string(&cfg).context("failed serializing config to string")?;
        let cphr = A::new_from_slice(&key).expect("config key is length 32");
        let iv = A::generate_nonce(OsRng);
        let encrypted_data = cphr.encrypt(&iv, data.as_bytes())?;

        let mut data = Vec::with_capacity(1024);

        data.extend(iv);
        data.extend(encrypted_data);

        Ok(Config {
            salt: salt.to_string(),
            cipher,
            data: b64.encode(data),
        })
    }

    fn init_config<A>(pw: &[u8], cipher: Cipher, digest: Digest, mode: Mode) -> Result<Config>
    where
        A: aead::Aead + aead::KeyInit,
    {
        let mut master_key: crypto::Key = [0u8; 32];
        OsRng.fill_bytes(&mut master_key);
        let mut dir_key = [0u8; 64];
        OsRng.fill_bytes(&mut dir_key);

        let cfg = SecretCfg {
            key: master_key,
            dir_key,
            cipher,
            digest,
            mode,
            check_digest: digest != Digest::None,
        };
        let cfg = Cli::encrypt_config::<A>(pw, cipher, cfg).context("Failed encrypting config")?;

        Ok(cfg)
    }

    fn decrypt_config<A>(pw: &[u8], cfg: &Config) -> Result<SecretCfg>
    where
        A: aead::Aead + aead::KeyInit,
    {
        debug!("{:?}", cfg);
        let mut bin_salt = [0u8; 16];
        SaltString::from_b64(&cfg.salt)
            .expect("salt has not been tampered with")
            .decode_b64(&mut bin_salt)
            .expect("is a valid salt");
        debug!("bin_salt={:?}", bin_salt);

        let mut key: crypto::Key = [0u8; 32];
        let _ = argon2::Argon2::default().hash_password_into(pw, &bin_salt, &mut key);

        let decoded = b64.decode(&cfg.data)?;
        let (iv, ciphertext) = decoded.split_at(12);

        let cipher = A::new_from_slice(&key).expect("config key is length 32");

        let decrypted_data = cipher.decrypt(iv.into(), ciphertext)?;
        let s = String::from_utf8(decrypted_data)?;

        let data: SecretCfg = toml::from_str(&s).expect("valid toml format");

        Ok(data)
    }

    fn load_config(encrypted_root: &str) -> Result<Config> {
        std::fs::metadata(encrypted_root).context("Encrypted root directory does not exist")?;
        let path = std::path::Path::new(&encrypted_root).join("fscryptrs.config");
        let mut file = std::fs::File::open(&path)
            .context("The encrypted_root directory does not contain config file")?;

        let mut data = String::new();
        file.read_to_string(&mut data)?;

        let cfg = toml::from_str(&data)?;
        Ok(cfg)
    }
    fn write_config(path: &std::path::Path, cfg: Config) -> Result<()> {
        let data = toml::to_string(&cfg)?;

        match std::fs::File::create_new(path) {
            Ok(mut file) => {
                file.write_all(data.as_bytes())?;
                info!("Successfully created config file at {:?}", path);
            }
            Err(e) => bail!("Failed initializing the filesystem; {}", e),
        };
        Ok(())
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize the filesystem
    Init {
        /// Password used for encryption of the filesystem
        /// Prompts the user for password if it's not specified at command invocation
        #[arg(short, long)]
        password: Option<String>,
        /// Directory where to initialize the encrypted filesystem
        encrypted_root: String,
        /// Cipher algorithm used for encryption
        #[arg(short, long,required=true, value_enum, default_value_t = Cipher::Aes256Gcm)]
        cipher: Cipher,
        /// Digest algorithm used for checking integrity of a file
        #[arg(short, long,required=true, value_enum, default_value_t = Digest::Blake2)]
        digest: Digest,
        /// File block aiignment
        #[arg(short, long,required=true, value_enum, default_value_t = Mode::Block)]
        mode: Mode,
    },
    /// Mount the filesystem
    Mount {
        /// Password used for encryption of the filesystem
        /// Prompts the user for password if it's not specified at command invocation
        #[arg(short, long)]
        password: Option<String>,
        /// Directory containing encrypted filesystem
        encrypted_root: String,
        /// Path where to mount the decrypted filesystem
        mount_point: String,
        /// FUSE options
        #[arg(short = 'o')]
        fuse_options: Option<String>,
    },
    /// Change password used for encryption
    Passwd {
        /// Directory containing encrypted filesystem
        encrypted_root: String,
    },
    /// Toggles the integrity checking of files
    Digest {
        /// Directory containing encrypted filesystem
        encrypted_root: String,
        /// Flag that controls file integrity checking
        #[arg(short, long, default_missing_value="true", num_args=0..=1)]
        check: bool,
    },
    /// Shows status of the encrypted root
    Status {
        /// Directory containing encrypted filesystem
        encrypted_root: String,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug, Serialize, Deserialize)]
enum Mode {
    /// IV/AuthTags are in metadata blocks followed by encrypted blocks
    Block,
    /// IV/AuthTag stored next to their respective encrypted block
    Stream,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Block => write!(f, "Block"),
            Mode::Stream => write!(f, "Stream"),
        }
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Digest::Blake2 => write!(f, "Blake2"),
            Digest::Sha3 => write!(f, "Sha3"),
            Digest::None => write!(f, "None"),
        }
    }
}

impl std::fmt::Display for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cipher::Aes256Gcm => write!(f, "Aes256Gcm"),
            Cipher::ChaCha20Poly1305 => write!(f, "ChaCha20Poly1305"),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug, Serialize, Deserialize)]
enum Digest {
    /// Blake2 hashing algorithm, faster on most hardware
    Blake2,
    /// Sha3 hashing algorithm, faster when CPU supports native AES instructions
    Sha3,
    /// Disable checking integrity of multiple blocks
    None,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug, Serialize, Deserialize)]
enum Cipher {
    /// Block cipher
    Aes256Gcm,
    /// Stream cipher
    ChaCha20Poly1305,
}

fn main() -> Result<()> {
    let args = Cli::parse();

    if args.debug {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .init();
    }

    match args.command {
        Commands::Init {
            encrypted_root,
            cipher,
            digest,
            mode,
            password: pw,
        } => {
            info!(
                "Initializing encrypted filesystem with cipher={}, digest={}, mode={} at {}",
                cipher, digest, mode, encrypted_root
            );

            let path = std::path::Path::new(&encrypted_root);
            let Ok(mut dir_iter) = path.read_dir() else {
                bail!("Encrypted root directory does not exist")
            };
            if dir_iter.next().is_some() {
                bail!("Encrypted root directory is not empty")
            }

            let pw = pw.unwrap_or_else(|| Cli::prompt_password().expect("Valid user password"));

            let cfg: Config = match cipher {
                Cipher::Aes256Gcm => Cli::init_config::<Aes>(pw.as_bytes(), cipher, digest, mode),
                Cipher::ChaCha20Poly1305 => {
                    Cli::init_config::<Cha>(pw.as_bytes(), cipher, digest, mode)
                }
            }
            .context("Failed initializing Config")?;

            let path = path.join("fscryptrs.config");
            Cli::write_config(&path, cfg).context("Failed initializing the filesystem")?;
        }
        Commands::Mount {
            encrypted_root,
            mount_point: mount,
            fuse_options,
            password: pw,
        } => {
            let _ = std::fs::metadata(&encrypted_root)
                .context("Encrypted root directory does not exist")?;
            let path = std::path::Path::new(&encrypted_root).join("fscryptrs.config");
            let mut file = std::fs::File::open(&path)
                .context("The encrypted_root directory does not contain config file")?;
            let mut data = String::new();
            file.read_to_string(&mut data)?;

            let cfg @ Config {
                salt: _,
                cipher,
                data: _,
            } = toml::from_str(&data)?;

            let pw = pw.unwrap_or_else(|| Cli::prompt_password().expect("Valid user password"));

            let SecretCfg {
                key,
                dir_key,
                cipher,
                digest,
                mode,
                check_digest,
            } = match cipher {
                Cipher::Aes256Gcm => Cli::decrypt_config::<Aes>(pw.as_bytes(), &cfg),
                Cipher::ChaCha20Poly1305 => Cli::decrypt_config::<Cha>(pw.as_bytes(), &cfg),
            }
            .context("Incorrect password. Rerun the command to try again...")?;

            let mut options = vec![MountOption::FSName("fscryptrs".to_string())];

            if let Some(opts) = fuse_options {
                options.extend(parse_fuse_options(&opts));
            }

            use caps::{CapSet, Capability};
            let Ok(permitted) = caps::read(None, CapSet::Permitted) else {
                bail!("failed reading permitted capabilities");
            };
            if !permitted.contains(&Capability::CAP_SYS_CHROOT) {
                bail!("Permitted capabilities does not contain CAP_SYS_CHROOT. Aborting...");
            }

            let Ok(_) = caps::raise(None, CapSet::Effective, Capability::CAP_SYS_CHROOT) else {
                bail!("Failed setting CAP_SYS_CHROOT into effective");
            };

            info!(
                "Mounting filesystem with {:?} cipher, {:?} digest in {:?} mode, with decrypted path at {:?} and underlying path at {:?}",
                cipher, digest, mode, mount, encrypted_root
            );
            println!(
                "Mounting filesystem at {} with encrypted data at {}",
                mount, encrypted_root
            );
            println!(
                "Using {:?} cipher, {:?} digest, and {:?} mode, digest checking set to {}",
                cipher, digest, mode, check_digest
            );

            let digest = if Digest::None == digest {
                Digest::Blake2
            } else {
                digest
            };

            match (cipher, digest, mode) {
                (Cipher::Aes256Gcm, Digest::Blake2, Mode::Block) => {
                    let fs = Fs::<Aes, Bl2, Blk>::new(encrypted_root, key, dir_key, check_digest);
                    fuser::mount2(fs, mount, &options)?;
                }
                (Cipher::Aes256Gcm, Digest::Blake2, Mode::Stream) => {
                    let fs = Fs::<Aes, Bl2, Stm>::new(encrypted_root, key, dir_key, check_digest);
                    fuser::mount2(fs, mount, &options)?;
                }
                (Cipher::Aes256Gcm, Digest::Sha3, Mode::Block) => {
                    let fs = Fs::<Aes, Sha, Blk>::new(encrypted_root, key, dir_key, check_digest);
                    fuser::mount2(fs, mount, &options)?;
                }
                (Cipher::Aes256Gcm, Digest::Sha3, Mode::Stream) => {
                    let fs = Fs::<Aes, Sha, Stm>::new(encrypted_root, key, dir_key, check_digest);
                    fuser::mount2(fs, mount, &options)?;
                }
                (Cipher::ChaCha20Poly1305, Digest::Blake2, Mode::Block) => {
                    let fs = Fs::<Cha, Bl2, Blk>::new(encrypted_root, key, dir_key, check_digest);
                    fuser::mount2(fs, mount, &options)?;
                }
                (Cipher::ChaCha20Poly1305, Digest::Blake2, Mode::Stream) => {
                    let fs = Fs::<Cha, Bl2, Stm>::new(encrypted_root, key, dir_key, check_digest);
                    fuser::mount2(fs, mount, &options)?;
                }
                (Cipher::ChaCha20Poly1305, Digest::Sha3, Mode::Block) => {
                    let fs = Fs::<Cha, Sha, Blk>::new(encrypted_root, key, dir_key, check_digest);
                    fuser::mount2(fs, mount, &options)?;
                }
                (Cipher::ChaCha20Poly1305, Digest::Sha3, Mode::Stream) => {
                    let fs = Fs::<Cha, Sha, Stm>::new(encrypted_root, key, dir_key, check_digest);
                    fuser::mount2(fs, mount, &options)?;
                }
                (_, Digest::None, _) => unreachable!(),
            };
        }
        Commands::Digest {
            encrypted_root,
            check,
        } => {
            println!("Setting digest checking to {}", check);
            let pw = rpassword::prompt_password("Please enter password: ")
                .context("No password was specified")?;

            let cfg @ Config {
                salt: _,
                cipher,
                data: _,
            } = Cli::load_config(&encrypted_root)?;

            let sec_cfg = match cipher {
                Cipher::Aes256Gcm => Cli::decrypt_config::<Aes>(pw.as_bytes(), &cfg),
                Cipher::ChaCha20Poly1305 => Cli::decrypt_config::<Cha>(pw.as_bytes(), &cfg),
            }
            .context("Incorrect password. Rerun the command to try again...")?;

            if sec_cfg.check_digest && check {
                println!("Digest checking is already turned on");
                return Ok(());
            }
            if !sec_cfg.check_digest && !check {
                println!("Digest checking is already turned off");
                return Ok(());
            }
            if !sec_cfg.check_digest && check {
                println!("Enabling digest checking with digest {}", sec_cfg.digest);
                //println!("Calculating digests for every file. This may take a while...");
                // TODO: implement calculating digests for every file
            }

            if sec_cfg.check_digest && !check {
                println!("Disabling digest checking");
                //println!("Removing digest files...");
                // TODO: implement removing digests for every file
            }

            println!("This feature is currently not fully supported");
            println!(
                "It only allows turning off and on digest checking on a filesystem which was
                initialized with either Blake2 or SHA3."
            );

            let new_sec_cfg = SecretCfg {
                check_digest: check,
                ..sec_cfg
            };
            let cfg = match cipher {
                Cipher::Aes256Gcm => Cli::encrypt_config::<Aes>(pw.as_bytes(), cipher, new_sec_cfg),
                Cipher::ChaCha20Poly1305 => {
                    Cli::encrypt_config::<Cha>(pw.as_bytes(), cipher, new_sec_cfg)
                }
            }?;

            let path = std::path::Path::new(&encrypted_root);
            let path_new = path.join("fscryptrs.config.new");

            Cli::write_config(&path_new, cfg).context("Failed writing new config")?;
            std::fs::rename(path_new, path.join("fscryptrs.config"))
                .context("Failed replacing old config with new")?;
        }

        Commands::Passwd { encrypted_root } => {
            println!("Changing the password used for encryption");
            let curr_pw = rpassword::prompt_password("Please enter current password ")
                .context("No password was specified")?;

            let new_pw = loop {
                let new_pw = rpassword::prompt_password("Please enter new password: ")
                    .context("No password was specified")?;

                let pw2 = rpassword::prompt_password("Retype the password: ")
                    .context("No password was specified")?;

                if new_pw == pw2 {
                    break new_pw;
                }
                println!("The passwords do not match. Try again.");
            };

            let cfg @ Config {
                salt: _,
                cipher,
                data: _,
            } = Cli::load_config(&encrypted_root)?;

            let sec_cfg = match cipher {
                Cipher::Aes256Gcm => Cli::decrypt_config::<Aes>(curr_pw.as_bytes(), &cfg),
                Cipher::ChaCha20Poly1305 => Cli::decrypt_config::<Cha>(curr_pw.as_bytes(), &cfg),
            }
            .context("Incorrect password. Rerun the command to try again...")?;

            let cfg = match cipher {
                Cipher::Aes256Gcm => Cli::encrypt_config::<Aes>(new_pw.as_bytes(), cipher, sec_cfg),
                Cipher::ChaCha20Poly1305 => {
                    Cli::encrypt_config::<Cha>(new_pw.as_bytes(), cipher, sec_cfg)
                }
            }?;

            let path = std::path::Path::new(&encrypted_root);
            let path_new = path.join("fscryptrs.config.new");

            Cli::write_config(&path_new, cfg).context("Failed initializing the filesystem")?;
            std::fs::rename(path_new, path.join("fscryptrs.config"))
                .context("Failed replacing old config with new")?;
        }
        Commands::Status { encrypted_root } => {
            let pw = rpassword::prompt_password("Please enter password: ")
                .context("No password was specified")?;

            let cfg @ Config {
                salt: _,
                cipher,
                data: _,
            } = Cli::load_config(&encrypted_root).context(
                "Supplied encrypted root does not appear to be a valid fscryptrs filesystem",
            )?;

            let sec_cfg = match cipher {
                Cipher::Aes256Gcm => Cli::decrypt_config::<Aes>(pw.as_bytes(), &cfg),
                Cipher::ChaCha20Poly1305 => Cli::decrypt_config::<Cha>(pw.as_bytes(), &cfg),
            }
            .context("Incorrect password. Rerun the command to try again...")?;

            println!("Showing status of directory `{}`", encrypted_root);
            println!();
            println!("Cipher: {}", sec_cfg.cipher);
            println!("Digest: {}", sec_cfg.digest);
            println!("Mode: {}", sec_cfg.mode);
            println!(
                "Digest checking is currently {}.",
                if sec_cfg.check_digest {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!();
        }
    }

    Ok(())
}

fn parse_fuse_options(opts: &str) -> Vec<MountOption> {
    let mut out = vec![];
    for x in opts.split(',') {
        out.push(fuse_args_from_str(x))
    }
    out
}

pub fn fuse_args_from_str(s: &str) -> MountOption {
    match s {
        "auto_unmount" => MountOption::AutoUnmount,
        "allow_other" => MountOption::AllowOther,
        "allow_root" => MountOption::AllowRoot,
        "default_permissions" => MountOption::DefaultPermissions,
        "ro" => MountOption::RO,
        "rw" => MountOption::RW,
        "sync" => MountOption::Sync,
        "async" => MountOption::Async,
        "dirsync" => MountOption::DirSync,
        "atime" => MountOption::Atime,
        "noatime" => MountOption::NoAtime,
        "dev" => MountOption::Dev,
        "nodev" => MountOption::NoDev,
        "suid" => MountOption::Suid,
        "nosuid" => MountOption::NoSuid,
        "exec" => MountOption::Exec,
        "noexec" => MountOption::NoExec,
        x => MountOption::CUSTOM(x.into()),
    }
}
