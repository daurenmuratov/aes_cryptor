use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use std::fs;

fn encrypt_file() {
    let plaintext = fs::read_to_string("Data\\input.txt").expect("Unable to read input file");
    let key_bytes = fs::read("Data/key.txt").expect("Unable to read key file");
    if key_bytes.len() != 32 {
        panic!("Key must be 32 bytes long");
    }
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(&key);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).expect("encryption failed");

    let mut output_data = nonce.to_vec();
    output_data.extend_from_slice(&ciphertext);
    fs::write("Data\\output.txt", &output_data).expect("Unable to write to output file");
}

fn decrypt_file() {
    let encrypted_data = fs::read("Data\\output.txt").expect("Unable to read output file");
    let (nonce, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce);

    let key_bytes = fs::read("Data/key.txt").expect("Unable to read key file");
    if key_bytes.len() != 32 {
        panic!("Key must be 32 bytes long");
    }
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(&key);

    let decrypted_plaintext = cipher.decrypt(nonce, ciphertext).expect("decryption failed");
    println!("{:?}", std::str::from_utf8(&decrypted_plaintext).expect("Invalid UTF-8"));
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
            1 => encrypt_file(),
            2 => decrypt_file(),
            3 => std::process::exit(0),
            _ => println!("Invalid choice"),
        }

        println!("Done");
    }
}
