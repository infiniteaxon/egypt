Welcome to Egypt!

This is a CLI tool for remote file storage with E2EE.

Features:
- SSL Encryption (You will need to create your own cert and key)
  - `openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt`
- Files on Server Encrypted at Rest
- Multiuser Support via Threading
- Upload
- Download
- List Stored Files
- Allow Subdirectory Creation and Storage
- Server Log Stored Externally
- Username / Password Auth
- Input Validation to prevent Directory Traversal

Plans:
- ???



**Images Below:**

Server:
- Logs

![image](https://github.com/infiniteaxon/egypt/assets/60622650/d70fbdfd-67c2-4776-b943-2959fa38f351)

- File at rest

![image](https://github.com/infiniteaxon/egypt/assets/60622650/b48e3570-d11e-4425-9940-b60019d6ca56)


Client:
- Interface
  
![image](https://github.com/infiniteaxon/egypt/assets/60622650/ff90b838-74ba-433e-b1ac-d95bbdf5923b)

![image](https://github.com/infiniteaxon/egypt/assets/60622650/39cfbc67-e6d8-4a25-ac2f-3782b8151999)

- File from download

![image](https://github.com/infiniteaxon/egypt/assets/60622650/25f0b969-be64-4d7b-b248-25d8ad5640d0)


