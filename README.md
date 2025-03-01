Welcome to Egypt!

This is a tool for remote file storage with E2EE.

Features:
- WebGUI
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
- Use SQL DB for Creds, Salting



**Images Below:**

Server:
- Logs

![image](https://github.com/infiniteaxon/egypt/assets/60622650/d70fbdfd-67c2-4776-b943-2959fa38f351)

- File at rest

![image](https://github.com/infiniteaxon/egypt/assets/60622650/b48e3570-d11e-4425-9940-b60019d6ca56)


Client:
- Login
  
![image](https://github.com/user-attachments/assets/76b3a0c8-ab7c-4822-bd24-0ee9344c1d45)

- Dashboard

![image](https://github.com/user-attachments/assets/fb1827b3-0655-481d-b585-de979b2a81eb)

- Upload

![image](https://github.com/user-attachments/assets/f94f82f5-1483-4c17-89a4-f94ee600060b)




- File from download

![image](https://github.com/infiniteaxon/egypt/assets/60622650/25f0b969-be64-4d7b-b248-25d8ad5640d0)


