# Security Camera Common

### This crate contains the common code used by a security camera video hosting server, and eventually for the client after I have programmed it


### Features:
* stream encryption and decryption using the stream macro provided by async-stream
* encrypts and decrypts files in chunks using aes-gcm
* has helper functions that use argon2 to generate salt, and also derive a key from a pre existing password.
* This project is meant to be used to send a stream of encrypted bytes over a web request, or decrypt a file from the file system and send the decrypted bytes in a stream.
