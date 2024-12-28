use crate::EncodedFrame;
use actix_web::web::Bytes;
use aes_gcm::aead::stream;
use aes_gcm::aead::stream::Encryptor;
use aes_gcm::aead::stream::StreamBE32;
use aes_gcm::aead::{Key, KeyInit};
use aes_gcm::Aes256Gcm;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::Argon2;
use async_stream::stream;
use base64::{engine, Engine};
use futures_core::Stream;
use shuttle_runtime::tokio;
use shuttle_runtime::tokio::io::AsyncReadExt;
use shuttle_runtime::tokio::sync::mpsc::Receiver;
use std::io::ErrorKind;
use tokio_stream::wrappers::ReceiverStream;

const BUFFER_LEN: usize = 3000;
const NONCE_LEN: usize = 16;
trait SizedError: std::error::Error + std::marker::Sized {}
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

// A wrapper struct that implements AsyncRead for a stream of frames
pub struct FrameReader<E: std::error::Error> {
    frames: Pin<Box<dyn Stream<Item = Result<Bytes, E>> + Send>>,
    current_frame: Option<Vec<u8>>,
    position: usize,
}

impl<E: std::error::Error + Send + 'static> FrameReader<E> {
    pub fn new<S>(frames: S) -> Self
    where
        S: Stream<Item = Result<Bytes, E>> + Send + 'static,
    {
        FrameReader {
            frames: Box::pin(frames),
            current_frame: None,
            position: 0,
        }
    }

    pub fn new_from_rx(rx: Receiver<Result<Bytes, E>>) -> Self {
        FrameReader {
            frames: Box::pin(ReceiverStream::new(rx)),
            current_frame: None,
            position: 0,
        }
    }
}

impl<E: std::error::Error> Drop for FrameReader<E> {
    fn drop(&mut self) {
        println!(
            "FrameReader dropped at position {} with {} bytes remaining",
            self.position,
            self.current_frame
                .as_ref()
                .map_or(0, |f| f.len() - self.position)
        );
    }
}

impl<E: std::error::Error> AsyncRead for FrameReader<E> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // If we have a current frame, try to read from it
            if let Some(frame) = self.current_frame.take() {
                let remaining = &frame[self.position..];
                let to_copy = std::cmp::min(remaining.len(), buf.remaining());

                buf.put_slice(&remaining[..to_copy]);
                self.position += to_copy;
                self.current_frame = Some(frame);

                // If we've read the entire frame, clear it
                if self.position >= self.current_frame.as_ref().unwrap().len() {
                    self.current_frame = None;
                    self.position = 0;
                }

                return Poll::Ready(Ok(()));
            }

            // Try to get the next frame
            match self.frames.as_mut().poll_next(cx) {
                Poll::Ready(Some(frame)) => {
                    self.current_frame = Some(
                        frame
                            .map_err(|e| std::io::Error::new(ErrorKind::Other, e.to_string()))?
                            .into(),
                    );
                    self.position = 0;
                    continue;
                }
                Poll::Ready(None) => {
                    println!("[COMMON] stream finished");
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

// Example usage with encryption
#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_frame_reader() {
        // Create a stream of frames
        let frames = stream::iter(vec![
            Ok(Bytes::from(vec![1, 2, 3])),
            Ok(Bytes::from(vec![4, 5, 6])),
            Ok(Bytes::from(vec![7, 8, 9])),
        ]);

        // Create a FrameReader
        let mut reader: FrameReader<std::io::Error> = FrameReader::new(frames);

        // Read all data
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).await.unwrap();

        assert_eq!(buffer, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }
}

pub fn encrypt_frame_reader<E: std::error::Error>(
    key: Key<Aes256Gcm>,
    salt: SaltString,
    mut frame_stream: FrameReader<E>,
    frame_size: usize,
) -> impl Stream<Item = Result<Vec<u8>, std::io::Error>> {
    let s = stream! {
        let b64_decoder = base64::engine::general_purpose::STANDARD_NO_PAD;
        let nonce = b64_decoder.decode(salt.as_str()).map_err(|e| {
            std::io::Error::new(ErrorKind::Other, e.to_string())
        })?;

        let mut buffer = vec![0u8; frame_size];

        let mut encryptor: Box<Encryptor<Aes256Gcm,StreamBE32<_>>> = Box::new(stream::EncryptorBE32::from_aead(
            Aes256Gcm::new(&key),
            nonce[0..7].into()
        ));
        yield Ok(nonce); // nonce will be appended to the beginning of the file
        let mut frame = Vec::new();
        loop {
            let read_count = frame_stream.read(&mut buffer).await?;
            if read_count == frame_size {
                let encrypted = encryptor.encrypt_next(&buffer[..])
                    .map_err(|e| std::io::Error::new(ErrorKind::Other, e.to_string()));
                yield Ok(encrypted?);
            } else if read_count == 0 {
                break;
            } else {
                frame = buffer[..read_count].to_vec();
            }
        }
        let encrypted = encryptor.encrypt_last(&frame[..])
            .map_err(|e| {
                std::io::Error::new(ErrorKind::Other, e.to_string())
            });
        yield Ok(encrypted?);
    };
    s
}

pub fn decrypt_frame_reader<E: std::error::Error>(
    mut encrypted_frame_stream: FrameReader<E>,
    frame_size: usize,
    password: String,
) -> impl Stream<Item = Result<Bytes, Box<dyn std::error::Error + 'static>>> {
    let s = stream! {
        // read in the salt
        let mut buffer = vec![0u8; frame_size+16];
        let mut salt = [0u8; NONCE_LEN];
        encrypted_frame_stream.read_exact(&mut salt).await?;
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
            let read_count = match encrypted_frame_stream.read_exact(&mut buffer).await {
                Ok(_) => {
                    buffer.len()
                }
                Err(e) => {
                    encrypted_frame_stream.read(&mut buffer).await?
                }
            };
            if read_count == frame_size+16 {
                let decrypted: Result<Vec<u8>, Box<dyn std::error::Error>> = decryptor.decrypt_next(&buffer[..]).map_err(|e|
                    {
                        e.to_string().into()
                    });
                yield Ok(Bytes::from(decrypted?));
            } else if read_count == 0 {
                break;
            } else {
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

#[deprecated]
pub fn encrypt_file_range(
    key: Key<Aes256Gcm>,
    salt: SaltString,
    files: Vec<String>,
) -> impl Stream<Item = Result<EncodedFrame, std::io::Error>> {
    let s = stream! {
        let b64_decoder = base64::engine::general_purpose::STANDARD_NO_PAD;
        let nonce = b64_decoder.decode(salt.as_str()).map_err(|e| {
            std::io::Error::new(ErrorKind::Other, e.to_string())
        })?;

        let mut buffer = [0u8; BUFFER_LEN];

        let mut encryptor: Box<Encryptor<Aes256Gcm,StreamBE32<_>>> = Box::new(stream::EncryptorBE32::from_aead(
            Aes256Gcm::new(&key),
            nonce[0..7].into()
        ));

        yield Ok(EncodedFrame::Nonce(nonce)); // nonce will be appended to the beginning of the file
        for filename in files {
            let mut last_chunk = Vec::new(); // stores the last file chunk that may be less than len BUFFER_LEN
            let mut file = tokio::fs::File::open(filename).await?;
            'inner: loop {
                let read_count = file.read(&mut buffer).await?;
                if read_count == BUFFER_LEN {
                    let encrypted = encryptor.encrypt_next(&buffer[..])
                        .map_err(|e| std::io::Error::new(ErrorKind::Other, e.to_string()));
                    yield Ok(EncodedFrame::FrameLast(encrypted?));
                } else if read_count == 0 {
                    break 'inner;
                } else {
                    last_chunk = buffer[..read_count].to_vec();
                }
            }
            let encrypted = encryptor.encrypt_next(&last_chunk[..])
                .map_err(|e| std::io::Error::new(ErrorKind::Other, e.to_string()));
            yield Ok(EncodedFrame::FrameLast(encrypted?));
        }

    };

    s
}

pub fn encrypt_stream(
    key: Key<Aes256Gcm>,
    salt: SaltString,
    mut file: tokio::fs::File,
) -> impl Stream<Item = Result<Vec<u8>, std::io::Error>> {
    let s = stream! {
        let b64_decoder = base64::engine::general_purpose::STANDARD_NO_PAD;
        let nonce = b64_decoder.decode(salt.as_str()).map_err(|e| {
            std::io::Error::new(ErrorKind::Other, e.to_string())
        })?;

        let mut buffer = [0u8; BUFFER_LEN];

        let mut encryptor = stream::EncryptorBE32::from_aead(
            Aes256Gcm::new(&key),
            nonce[0..7].into()
        );
        let mut last_chunk = Vec::new(); // stores the last file chunk that may be less than len BUFFER_LEN
        yield Ok(nonce); // nonce will be appended to the beginning of the file
        loop {
            let read_count = file.read(&mut buffer).await?;
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

#[deprecated]
pub fn encrypt_stream_frame<T: AsyncReadExt + std::marker::Unpin>(
    key: Key<Aes256Gcm>,
    salt: SaltString,
    mut data: T,
) -> impl Stream<Item = Result<Vec<u8>, std::io::Error>> {
    let s = stream! {
        let b64_decoder = base64::engine::general_purpose::STANDARD_NO_PAD;
        let nonce = b64_decoder.decode(salt.as_str()).map_err(|e| {
            std::io::Error::new(ErrorKind::Other, e.to_string())
        })?;

        let mut buffer = [0u8; BUFFER_LEN];

        let mut encryptor = stream::EncryptorBE32::from_aead(
            Aes256Gcm::new(&key),
            nonce[0..7].into()
        );
        let mut last_chunk = Vec::new(); // stores the last file chunk that may be less than len BUFFER_LEN
        yield Ok(nonce); // nonce will be appended to the beginning of the file
        loop {
            let read_count = data.read(&mut buffer).await?;
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

#[deprecated]
pub fn decrypt_stream_frame<T: AsyncReadExt + std::marker::Unpin>(
    mut data: T,
    password: String,
) -> impl Stream<Item = Result<Bytes, Box<dyn std::error::Error + 'static>>> {
    let s = stream! {
        // read in the salt
        let mut buffer = [0u8; BUFFER_LEN+16];
        let mut salt = [0u8; NONCE_LEN];
        data.read_exact(&mut salt).await?;
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
            let read_count = data.read(&mut buffer).await?;
            if read_count == BUFFER_LEN+16 {
                let decrypted: Result<Vec<u8>, Box<dyn std::error::Error>> = decryptor.decrypt_next(&buffer[..]).map_err(|e|
                    {
                        println!("got an error: {:?}",e);
                        e.to_string().into()
                    });
                yield Ok(Bytes::from(decrypted?));
            }else if read_count == 0 {
                println!("no bytes read");
                break;
            } else {
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

pub fn decrypt_stream(
    mut file: tokio::fs::File,
    password: String,
) -> impl Stream<Item = Result<Bytes, Box<dyn std::error::Error + 'static>>> {
    let s = stream! {
        // read in the salt
        let mut buffer = [0u8; BUFFER_LEN+16];
        let mut salt = [0u8; NONCE_LEN];
        file.read_exact(&mut salt).await?;
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
            let read_count = file.read(&mut buffer).await?;
            if read_count == BUFFER_LEN+16 {
                let decrypted: Result<Vec<u8>, Box<dyn std::error::Error>> = decryptor.decrypt_next(&buffer[..]).map_err(|e|
                    {
                        println!("got an error: {:?}",e);
                        e.to_string().into()
                    });
                yield Ok(Bytes::from(decrypted?));
            }else if read_count == 0 {
                println!("no bytes read");
                break;
            } else {
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

/// returns (key, salt)
pub fn generate_key(
    password: &str,
) -> Result<(Key<Aes256Gcm>, SaltString), Box<dyn std::error::Error>> {
    let mut key_out = [0u8; 32];
    let salt = SaltString::generate(&mut OsRng);
    let b64_decoder = engine::general_purpose::STANDARD_NO_PAD;
    let salt_bytes = b64_decoder.decode(salt.as_str())?;
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt_bytes, &mut key_out)
        .map_err(|e| e.to_string())?;
    Ok((key_out.into(), salt))
}

/// salt should be made by base64 decoding a SaltString
pub fn generate_keystream(
    password: &str,
    salt: &[u8],
) -> Result<Key<Aes256Gcm>, Box<dyn std::error::Error>> {
    let mut key_out = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key_out)
        .map_err(|e| e.to_string())?;
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
