# crypto
Golang crypto code... right now I have a spritz cipher (see [RS14.pdf][2])

## Spritz Cipher
I have implemented the spritz cipher for hashing and encryption in several 
languages in my [spritz_cipher repo][1].  There is even a golang version
there, but it doesn't provide a library and only does hashing.

This is a fully-featured golang implementation of spritz, which
provides a `hash.Hash` interface for hashing and a `crypto/cipher.Stream`
interface for encryp/decrypt.  

It also provides commands that use the library for hashing and 
encrypting/decrypting files.

### Library
You can get the spritz library by:

    go get github.com/waywardcode/crypto/spritz

As I mentioned, it provides standard interfaces, and is
easy to use if you know golang's standard hashes and streams.  For instance,
here is some example code for hashing:

    // 256-bit hash of a byte slice:
    hash := spritz.Sum(256, buffer)
    
    // 512-bit hash of a file (ignoring errors for brevity)
    infile, _ := os.Open(fname)
    shash := spritz.NewHash(512)
    io.Copy(shash, infile)
    infile.Close()
    hash := shash.Sum(nil)

### Commands

You can get the commands like so:

    go get github.com/waywardcode/crypto/cmd/spritz-hash
    go get github.com/waywardcode/crypto/cmd/spritz-crypt

The hasher is a concurrent program, which will hash up to 8 files at once as it works
through the list.  It takes a "--size" parameter to get the hash size in bits.  
The encrypt/decrypt program just works on a single file at a time.  It just takes
the pasword on the command line, which isn't ideal, but fine for test code.

[1]: https://github.com/waywardcode/spritz_cipher
[2]: http://people.csail.mit.edu/rivest/pubs/RS14.pdf
