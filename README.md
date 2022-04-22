![HEADER|FI](http://www.hondaprokevin.com/pictures/generic-site-art/red-gray-header-footer.png)
[![UNAM|FI](https://www.ingenieria.unam.mx/images/logos/logo_2.png)](https://www.ingenieria.unam.mx/)

#  Cryptography 🔐
## Project 1
_________________
---
This project consists of a program that compares the efficiency of the algorithms listed below. The program generates a set of test vectors for each algorithm and, after execution, displays the results of each algorithm using graphs according to the goals shared and operations.
The operations are:
- Encryption 🔒
- Decryption 🔓
-  Hashing  #️⃣
-  Signing ✍️
- Verifying ✅

The algorithms to compare and analyze are the following:

| Algorithm | Size |
| ------ | ------ |
| Chacha20 | Key Size 256 bits |
| AES-EBC | Key Size 256 bits |
| AES-GCM | Key Size 256 bits |
| SHA-2 | Hash size 384 bits |
| SHA-2 | Hash size 512 bits |
| SHA-3 | Hash size 384 bits |
| SHA-3 | Hash size 512 bits |
| RSA-OAEP | 2048 bits |
| RSA-PSS | 2048 bits |
| ECDSA Prime Field | ECDSA, 521 Bits (Prime Field) |
| ECDSA Binary Field |ECDSA, 571 Bits (Binary Field, Koblitz Curve)|

### Running the program
---

To execute the program is it necessary to have python3 installed and follow the next commands:


```sh
cd <PATH_OF_THE_PROJECT>
python3 main.py
```
Main.py installs all the modules needed to run the program and it executes it.


### Modules 
---
The project uses a number of modules to get the algorithms and work properly:
- pycryptodome -- crypto algorithms
 - cryptography -- crypto algorithms
- matplotlib --used to graph.
- ecdsa -- eliptic curves algorithms




   ![HEADER|FI](http://www.hondaprokevin.com/pictures/generic-site-art/red-gray-footer-header.png)
