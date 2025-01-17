# Security Camera Common

### This crate contains the common code used by the security camera server, and the security camera client.


### Features:
* Stream encryption and decryption using the stream macro provided by async-stream.
* Encrypts and decrypts files in chunks using aes-gcm.
* Has helper functions that use argon2 to generate salt, and also derive a key from a pre existing password.
* This project is meant to be used to send a stream of encrypted bytes over a web request, or decrypt a file from the file system and send the decrypted bytes in a stream.
* Uses a FrameReader struct that implements AsyncRead for easy integration with streams and encryption helper functions.

## Crates:
Server (Front end, Video hosting, session based login): https://github.com/matthewashton-k/security-cam-server
Client (motion detection, v4l, frame processing): https://github.com/matthewashton-k/security-cam-client
