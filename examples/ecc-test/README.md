ECC-test
===========

This tests ECC key pair generation, ECDH shared key generation and ECDSA generation and verification. 
First 2 ECC key pairs are generated for 2 different users. The time that takes to perform this task
is shown. After that, the function to generate the shared secret is called 2 times. 
The first using Alice's secret key and Bob's public key. The second time using Bob's secret key 
and Alice's public key.
After that Alice signs using her private key the message Hello Bob. Bob receives the message and the signature and verifies it.
