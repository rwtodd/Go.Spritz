# Go.Spritz
Golang spritz cipher (see [RS14.pdf][2])

## Spritz Cipher
I have implemented the spritz cipher for hashing and encryption in several 
languages in my [spritz\_cipher repo][1].  There is even a golang version
there, but it doesn't provide a library and only does hashing.

This is a fully-featured golang implementation of spritz, which
provides a `hash.Hash` interface for hashing and a `crypto/cipher.Stream`
interface for encryp/decrypt.  

It also provides commands that use the library for hashing and 
encrypting/decrypting files.

### Library
You can get the spritz library by:

    go get github.com/rwtodd/Go.Spritz/spritz

As I mentioned, it provides standard interfaces, and is
easy to use if you know golang's standard hashes and streams.  For instance,
here is some example code for hashing:

    import "github.com/rwtodd/Go.Spritz/spritz"

    // 256-bit hash of a byte slice:
    hash := spritz.Sum(256, buffer)
    
    // 512-bit hash of a file (ignoring errors for brevity)
    infile, _ := os.Open(fname)
    shash := spritz.NewHash(512)
    io.Copy(shash, infile)
    infile.Close()
    hash := shash.Sum(nil)

### Command

You can get the command-line driver like so:

    go get github.com/rwtodd/Go.Spritz/cmd/spritz

The hasher is a concurrent program, which will hash up to 8 files at once as it works
through the list.  It takes a "--size" parameter to get the hash size in bits.  
The encrypt/decrypt program is also concurrent. 

[1]: https://github.com/rwtodd/spritz_cipher
[2]: http://people.csail.mit.edu/rivest/pubs/RS14.pdf
