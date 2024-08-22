# webBasedChatApplication_ClientServerModel
This is Pyhton code of client and server for my chat application model.


This Code have features like sent and received tags, time stamp, to determine when message was sent, and Messages are Encrypted using Advanced Cryptographic Standard(AES) Algorithm.

While the key used for encrption is derived from user-input pre shared key, which is hashed using SHA-256 hashing algorithm, to ensure it is 32bytes (256 bits long) which therby is suitable for AES-256 encryption.

The code breaks the data into blocks of 16 bytes, encrypts each block with the AES algorithm, and handles padding by adding tilde characters (~) for blocks that are less than 16 bytes.
