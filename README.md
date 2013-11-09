csharp-evil-twin
================

A cryptography algorithm using twin messages with complementary distortion.  
BSD license.  

##How It Works

Alice needs to send a secret key to Bob.  
The key is split into two parts, A and B and sent to Bob.  
Only Bob receives the two parts.  

Each part Alice sends is encrypted using prime number compositions.  
Among the 15 lowest prime numbers, 8 primes are selected to encode the message.  
The remaining 7 primes are used to distort the message.  
This equals inserting 7 fake bits for every 8 bits in the message.  

Since Alice uses prime number composition, one byte is translated to 8 encrypted bytes.  
This results in 16 times more data, but works nicely for small files.  

For an attacker only receiving one part, there are in worst case 1820 ways to interpret the message.  
In practice this number is lower due to 0 being inserted between 0's etc.  
Since a byte only contain 256 different values, reading one part is pretty useless.  

##How To Use It

    // A buffer array is required to do encryption.
    var buf = EvilTwinModule.CreateBufferArray();
    UInt64 a, b;
    byte msg = 42;
    var rnd = new Random();
    // Split the message into two parts.
    EvilTwinModule.Encrypt(rnd, buf, msg, out a, out b);
    // Read the secret message.
    var answer = EvilTwinModule.Decrypt(a, b);
    
  
    
