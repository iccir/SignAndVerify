SignAndVerify
=============

Demonstration of how to generate an RSA private/public keypair via OpenSSL and sign and verify on both OS X and iOS.

Keys created with the following commands:

    openssl genrsa -out private_key.pem 768
    openssl rsa -in private_key.pem -pubout -out public_key.pem

General flow:

    1) Run OS X target
    2) Private key is imported using SecItemImport
    3) For each line in input.txt, a SHA-1 and SHA-256 hash is generated.  
    4) Each hash is then signed using the private key, using SecTransform
    5) The resulting hashes and signatures are saved in results.txt
    6) Public key is imported using SecItemImport
    7) Hashes and signatures are verified.  Again via SecTransform
    
    6) Run iOS target
    7) Private key is imported
    8) input.txt is parsed, hashes made, and verified against results.txt
       (results.txt was generated from the OS X target)
    9) in-memory hashes and signatures verified against public key
  
Resources that helped:

    - http://blog.flirble.org/2011/01/05/rsa-public-key-openssl-ios/
    - http://blog.wingsofhermes.org/?p=42
    - http://blog.wingsofhermes.org/?p=75
