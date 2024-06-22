use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use std::fs;
use std::io::{Error, ErrorKind};

fn encrypt_file() -> Result<(), Error> {
    let plaintext = fs::read_to_string("Data\\input.txt")?;
    let key_bytes = fs::read("Data/key.txt")?;
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(&key);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = match cipher.encrypt(&nonce, plaintext.as_bytes()) {
        Ok(ciphertext) => ciphertext,
        Err(_) => {
            return Err(Error::new(ErrorKind::Other, "Encryption failed"))
        },
    };

    let mut output_data = nonce.to_vec();
    output_data.extend_from_slice(&ciphertext);
    fs::write("Data\\output.txt", &output_data)?;
    Ok(())
}

fn decrypt_file() -> Result<(), Error> {
    let encrypted_data = fs::read("Data\\output.txt")?;
    let (nonce, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce);

    let key_bytes = fs::read("Data/key.txt")?;
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(&key);

    let decrypted_plaintext = match cipher.decrypt(nonce, ciphertext) {
        Ok(decrypted_plaintext) => decrypted_plaintext,
        Err(_) => {
            return Err(Error::new(ErrorKind::Other, "Decryption failed"))
        },
    };
    println!("{:?}", std::str::from_utf8(&decrypted_plaintext));
    Ok(())
}

fn main() {
    loop {
        println!("AES-GCM Encryption/Decryption Example");
        println!("Choose an option:");
        println!("1. Encrypt");
        println!("2. Decrypt");
        println!("3. Exit");

        let mut choice = String::new();
        std::io::stdin().read_line(&mut choice).expect("Failed to read line");
        let choice: u32 = choice.trim().parse().expect("Please type a number");
        match choice {
            1 => match encrypt_file() {
                Ok(_) => println!("Done"),
                Err(err) => println!("Error: {:?}", err),
            },
            2 => match decrypt_file() {
                Ok(_) => println!("Done"),
                Err(err) => println!("Error: {:?}", err),
            },
            3 => std::process::exit(0),
            _ => println!("Invalid choice"),
        }
    }
}
