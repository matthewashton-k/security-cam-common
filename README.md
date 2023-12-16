# Security Camera Common

### This crate contains the common code used by a security camera video hosting server, and eventually for the client after I have programmed it


### Features:
* stream encryption and decryption using the stream macro provided by async-stream
* encrypts and decrypts files in chunks using aes-gcm
* has helper functions that use argon2 to generate salt, and also derive a key from a pre existing password.
* This project is meant to be used to send a stream of encrypted bytes over a web request, or decrypt a file from the file system and send the decrypted bytes in a stream.


### Testing:
* the tests rely on test files in https://gitlab.com/matthewashton_k/secure-mp4-host, if you clone that repo there are existing mp4s in the assets/ directory so that it makes it easier to test both crates by generating encrypted files in this project, and then testing the hosting of those files in the other project.
I may move the test .mp4 files to this repo in the future but currently since this is just a personal project meant to be used with secure-mp4 host I haven't bothered.
