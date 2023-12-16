use std::io::ErrorKind;
use actix_web::web::{Bytes};
use aes_gcm::aead::stream;
use aes_gcm::aead::{Key, KeyInit};

use aes_gcm::Aes256Gcm;
use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use async_stream::stream;
use base64::{Engine, engine};
use futures_core::Stream;
use shuttle_runtime::tokio;
use shuttle_runtime::tokio::io::AsyncReadExt;


const BUFFER_LEN: usize = 500;
const NONCE_LEN: usize = 16;
trait SizedError: std::error::Error + std::marker::Sized {}

/// Used for encrypting and decrypting a file
pub struct EncryptDecrypt {
    pub key: Option<Key<Aes256Gcm>>,
    pub salt: Option<SaltString>,
    pub file: tokio::fs::File
}

impl EncryptDecrypt {

    /// reads in chunks of bytes from self.file, then encrypts them using a key generated from random salt and the password parameter
    pub fn decrypt_stream(mut self,password: String) -> impl Stream<Item=Result<Bytes, Box<dyn std::error::Error + 'static>>> {
        let s = stream! {
            // read in the salt
            let mut buffer = [0u8; BUFFER_LEN+16];
            let mut salt = [0u8; NONCE_LEN];
            self.file.read_exact(&mut salt).await?;
            let salt = salt.to_vec();

            // generate key from salt and password
            let key = generate_keystream(&password,&salt)?;
            let mut decryptor = stream::DecryptorBE32::from_aead(
                Aes256Gcm::new(&key),
                (&salt[0..7]).into()
            );
            // will store the last chunk of data that could be less than BUFFER_LEN
            let mut last_chunk = Vec::new();
            loop {
                let read_count = self.file.read(&mut buffer).await?;
                if read_count == BUFFER_LEN+16 {
                    let decrypted: Result<Vec<u8>, Box<dyn std::error::Error>> = decryptor.decrypt_next(&buffer[..]).map_err(|e|
                        {
                            println!("got an error: {:?}",e);
                            e.to_string().into()
                        });
                    yield Ok(Bytes::from(decrypted?));
                }else if read_count == 0 {
                    break;
                } else{
                    last_chunk = buffer[..read_count].to_vec();
                }
            }
            let decrypted: Result<Vec<u8>, Box<dyn std::error::Error>> = (decryptor)
                .decrypt_last(&last_chunk[..])
                .map_err(|e| e.to_string().into());
            yield Ok(Bytes::from(decrypted?));
        };
        s
    }

    /// self.file, self.salt, and self.key should be Some before using this function.
    /// keys and salt can be generated using the generate_key function
    /// salt writen to the first 12 bytes of file
    /// only the first 7 of those bytes need to be used for the AESGCM cypher's salt but all 12 should be used to generate the key stream
    pub fn encrypt_stream(mut self) -> impl Stream<Item=Result<Vec<u8> , std::io::Error>> {
        let s = stream! {
            if self.key.is_none() || self.salt.is_none() { // if no nonce is found
                yield Err(std::io::Error::new(ErrorKind::Other, "nonce or key not found")); // yeilding an error will stop stream
            }
            let b64_decoder = base64::engine::general_purpose::STANDARD_NO_PAD;
            let nonce = b64_decoder.decode(self.salt.unwrap().as_str()).map_err(|e| {
                std::io::Error::new(ErrorKind::Other, e.to_string())
            })?;

            let mut buffer = [0u8; BUFFER_LEN];

            let mut encryptor = stream::EncryptorBE32::from_aead(
                Aes256Gcm::new(&self.key.unwrap()),
                nonce[0..7].into()
            );
            let mut last_chunk = Vec::new(); // stores the last file chunk that may be less than len BUFFER_LEN
            yield Ok(nonce); // nonce will be appended to the beginning of the file
            loop {
                let read_count = self.file.read(&mut buffer).await?;
                if read_count == BUFFER_LEN {
                    let encrypted = encryptor.encrypt_next(&buffer[..])
                        .map_err(|e| std::io::Error::new(ErrorKind::Other, e.to_string()));
                    yield encrypted;
                } else if read_count == 0 {
                    break;
                } else {
                    last_chunk = buffer[..read_count].to_vec();
                }
            }
            let encrypted = (encryptor)
                .encrypt_last(&last_chunk[..])
                .map_err(|e| std::io::Error::new(ErrorKind::Other, e.to_string()));
            yield encrypted;
        };
        s // return the stream
    }

}



/// returns (key, salt)
pub fn generate_key(password: &str) -> Result<(Key<Aes256Gcm>,SaltString), Box<dyn std::error::Error>> {
    let mut key_out = [0u8; 32];
    let salt = SaltString::generate(&mut OsRng);
    let b64_decoder = engine::general_purpose::STANDARD_NO_PAD;
    let salt_bytes = b64_decoder.decode(salt.as_str())?;
    Argon2::default().hash_password_into(password.as_bytes(), &salt_bytes, &mut key_out).map_err(|e|e.to_string())?;
    Ok((key_out.into(),salt ))
}

/// salt should be made by base64 decoding a SaltString
pub fn generate_keystream(password:&str,salt: &[u8]) -> Result<Key<Aes256Gcm>, Box<dyn std::error::Error>> {
    let mut key_out = [0u8; 32];
    Argon2::default().hash_password_into(password.as_bytes(), salt, &mut key_out).map_err(|e|e.to_string())?;
    Ok(key_out.into())
}


// /// currently only used for testing purposes
// fn encrypt_bytes(key: &Key<Aes256Gcm>,salt:SaltString, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
//     let cipher = Aes256Gcm::new(key);
//     let salt  = salt.to_string();
//     // nonce only needs to be 12 bytes for aesgcm
//     Ok(cipher.encrypt(salt.as_bytes()[0..12].into(), plaintext).map_err(|e| {e.to_string()})?)
// }
//
// pub fn decrypt_bytes(key: &Key<Aes256Gcm>,salt:SaltString, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
//     let cipher = Aes256Gcm::new(key);
//     Ok(cipher.decrypt(salt.to_string().to_string().as_bytes()[0..12].into(), ciphertext).map_err(|e| {e.to_string()})?)
// }


#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio_stream::StreamExt;
    
    
    use std::fs::remove_file;


    #[actix_web::test]
    async fn test_encrypt_decrypt() -> Result<(), Box<dyn std::error::Error>> {
        let password = "test_password";
        let (key, salt) = generate_key(password)?;

        let test_data = "This is some test data";
        let tmp_file_path = "/var/tmp/test_file.txt";
        let mut tmp_file = tokio::fs::File::create(tmp_file_path).await?;
        tmp_file.write_all(test_data.as_bytes()).await?;

        let file = tokio::fs::File::open(tmp_file_path).await?;
        let decryptor = EncryptDecrypt { key: Some(key), salt: Some(salt.clone()), file };
        let mut encrypted_stream = Box::pin(decryptor.encrypt_stream());

        let tmp_file_path2 = "/var/tmp/test_file2.txt";
        let mut tmp_file2 = tokio::fs::File::create(tmp_file_path2).await?;
        while let Some(chunk) = encrypted_stream.next().await {
            tmp_file2.write_all(&chunk.unwrap()).await?;
        }

        let file2 = tokio::fs::File::open(tmp_file_path2).await?;
        let decryptor2 = EncryptDecrypt { key: None, salt: None, file: file2 };
        let mut decrypted_stream = Box::pin(decryptor2.decrypt_stream("test_password".to_owned()));

        let mut decrypted_data = Vec::new();
        while let Some(chunk) = decrypted_stream.next().await {
            let chunk = chunk?;
            decrypted_data.extend_from_slice(&chunk);
        }

        assert_eq!(test_data.as_bytes(), decrypted_data.as_slice());

        remove_file(tmp_file_path)?;
        remove_file(tmp_file_path2)?;

        Ok(())
    }

//[185, 98, 129, 140, 41, 117, 231, 167, 137, 212, 236, 150, 200, 239, 79, 243, 74, 202, 15, 47, 96, 120, 7, 119, 221, 245, 67, 63, 242, 102, 230, 52]
// [80, 103, 76, 121, 102, 75, 111, 120, 67, 84, 47, 56, 86, 70, 112, 106, 65, 78, 73, 56, 76, 65]

    #[actix_web::test]
    async fn make_encrypted_file() -> Result<(), Box<dyn std::error::Error>>  {
        let password = "pass";
        let (key, salt) = generate_key(password)?;
        println!("encryptedfile:{key:?}{:?}",&salt.to_string().as_bytes());
        let file = tokio::fs::File::open("../security-cam-viewer/assets/test-2023-11-21_17.58.46.mp4").await?;
        let decryptor = EncryptDecrypt { key: Some(key), salt: Some(salt.clone()), file };
        let mut encrypted_stream = Box::pin(decryptor.encrypt_stream());

        let tmp_file_path2 = "../security-cam-viewer/assets/test-enc2-2023-11-21_17.58.46.mp4";
        let mut tmp_file2 = tokio::fs::File::create(tmp_file_path2).await?;
        while let Some(chunk) = encrypted_stream.next().await {
            tmp_file2.write_all(&chunk.unwrap()).await?;
        }
        Ok(())
    }
}


