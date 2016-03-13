// A rudimentary encryptor-decryptor.
// More options and concurrency are coming.

package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.waywardcode.com/spritz"
)

// Command-line switches ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
var pw string        // the password in effect
var jobs int         // the number of concurrent jobs to run
var outdir string    // the output directory
var decryptMode bool // should we decrypt?  Default is to encrypt.
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

func init() {
	flag.StringVar(&pw, "password", "", "the password to use for encryption/decryption")
	flag.StringVar(&pw, "p", "", "shorthand for --password")
	flag.StringVar(&outdir, "odir", "", "the output directory")
	flag.StringVar(&outdir, "o", "", "shorthand for --odir")
	flag.IntVar(&jobs, "jobs", 2, "number of concurrent files to work on")
	flag.IntVar(&jobs, "j", 2, "shorthand for --jobs")
	flag.BoolVar(&decryptMode, "d", false, "shorthand for --decrypt")
	flag.BoolVar(&decryptMode, "decrypt", false, "decrypt the files")
}

func odir(in string) string {
	// if no odir was specified, don't change the directory
	if len(outdir) == 0 {
		return in
	}

	// otherwise, put the output file in the specified directory
	base := filepath.Base(in)
	return filepath.Join(outdir, base)
}

func encrypt(pw, fn string) error {
	// we need random data for the IV and authentication token
	var rdata = make([]byte, 8)
	_, err := rand.Read(rdata)
	if err != nil {
		return err
	}

	var inFile, outFile *os.File
	if fn == "-" {
		inFile, outFile = os.Stdin, os.Stdout
	} else {
		encn := odir(fn + ".spritz")
		fmt.Printf("%s -> %s\n", fn, encn)

		inFile, err = os.Open(fn)
		if err != nil {
			return err
		}
		defer inFile.Close()

		outFile, err = os.OpenFile(encn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			return err
		}
		defer outFile.Close()
	}

	outFile.Write(rdata[:4]) // write the IV unencrypted!

	writer := &cipher.StreamWriter{S: spritz.NewStream(pw, rdata[:4]), W: outFile}
	_, err = writer.Write(rdata[4:])                   // write the authentication token
	_, err2 := writer.Write(spritz.Sum(32, rdata[4:])) // write the hash of the token
	if err != nil || err2 != nil {
		return fmt.Errorf("Couldn't write the authentication token!")
	}

	_, err = io.Copy(writer, inFile)
	return err
}

func decrypt(pw, fn string) error {

	var inFile, outFile *os.File
	var err error

	// setup the input
	if fn == "-" {
		inFile = os.Stdin
	} else {
		inFile, err = os.Open(fn)
		if err != nil {
			return err
		}
		defer inFile.Close()
	}

	iv := make([]byte, 4)
	_, err = io.ReadFull(inFile, iv)
	if err != nil {
		return err
	}

	reader := &cipher.StreamReader{S: spritz.NewStream(pw, iv), R: inFile}

	authdata := make([]byte, 8)
	_, err = io.ReadFull(reader, authdata) // read the authentication token
	if err != nil {
		return err
	}

	check := spritz.Sum(32, authdata[:4])
	if !bytes.Equal(check, authdata[4:]) {
		return fmt.Errorf("%s Bad password or corrupted file!", fn)
	}

	// input looks good, so set up the output
	if fn == "-" {
		outFile = os.Stdout
	} else {
		var decn string
		if strings.HasSuffix(fn, ".spritz") {
			decn = fn[:len(fn)-7]
		} else {
			decn = fn + ".decrypted"
		}
		decn = odir(decn)
		fmt.Printf("%s -> %s\n", fn, decn)

		outFile, err = os.OpenFile(decn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			return err
		}
		defer outFile.Close()
	}

	_, err = io.Copy(outFile, reader)
	return err
}

func main() {
	flag.Parse()

	if len(pw) == 0 {
		fmt.Fprintf(os.Stderr, "Missing password.\n")
		flag.Usage()
		return
	}

	// select the encryption/decryption function
	var process func(string, string) error
	if decryptMode {
		process = decrypt
	} else {
		process = encrypt
	}

	// no filenames means act as a filter
	files := flag.Args()
	if len(files) == 0 {
		files = append(files, "-")
	}

	var limiter = make(chan struct{}, jobs)
	var wg sync.WaitGroup
	wg.Add(len(files))

	var hadErrors bool  // is bool change atomic? surely so... need to check RWT

	for _, fname := range files {
		go func(fname string) {
			defer wg.Done()

			limiter <- struct{}{}
			if err := process(pw, fname); err != nil {
				fmt.Fprintf(os.Stderr,"%v\n",err)
				hadErrors = true
			}
			<-limiter
		}(fname)
	}

	wg.Wait()

	if hadErrors {
		os.Exit(1)
        }
}
