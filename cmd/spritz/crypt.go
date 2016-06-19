// A rudimentary encryptor-decryptor.

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
	"go.waywardcode.com/terminal/password"
)

// Command-line switches ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
var pw string        // the password in effect
var outdir string    // the output directory
var decryptMode bool // should we decrypt?  Default is to encrypt.
var checkMode bool   // should we just check the file/pw combo?
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
	var err error

	// we need random data for the IV and authentication token
	var header = make([]byte, 9)
	header[0] = 1
	if _, err = rand.Read(header[1:]); err != nil {
		return err
	}

	var inFile, outFile *os.File
	var embeddedName []byte
	if fn == "-" {
		inFile, outFile = os.Stdin, os.Stdout
		embeddedName = append(embeddedName, 0)
	} else {
		baseName := []byte(filepath.Base(fn))
		embeddedName = append(embeddedName, byte(len(baseName)))
		embeddedName = append(embeddedName, baseName...)

		encn := odir(fn + ".spritz")
		fmt.Printf("%s -> %s\n", fn, encn)

		if inFile, err = os.Open(fn); err != nil {
			return err
		}
		defer inFile.Close()

		outFile, err = os.OpenFile(encn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			return err
		}
		defer outFile.Close()
	}

	outFile.Write([]byte{1})
	outFile.Write(header[1:5]) // write the IV unencrypted!

	writer := &cipher.StreamWriter{S: spritz.NewStream(pw, header[1:5]), W: outFile}
	_, err = writer.Write(header[5:])                   // write the authentication token
	_, err2 := writer.Write(spritz.Sum(32, header[5:])) // write the hash of the token
	_, err3 := writer.Write(embeddedName)
	if err != nil || err2 != nil || err3 != nil {
		return fmt.Errorf("Couldn't write the file header!")
	}

	_, err = io.Copy(writer, inFile)
	return err
}

// initDecryption sets up a decryption, by checking that the password
// is correct, and parsing out the original filename if it's there.
// It returns the io.Reader to read decrypted bytes, the base
// *os.File for the caller to close, the filename, and any errors
// it encountered.
func initDecryption(pw, fn string) (io.Reader, *os.File, string, error) {
	var inFile *os.File
	var err error

	// setup the input
	if fn == "-" {
		inFile = os.Stdin
	} else {
		if inFile, err = os.Open(fn); err != nil {
			return nil, nil, "", err
		}
	}

	header := make([]byte, 5)
	if _, err = io.ReadFull(inFile, header); err != nil {
		return nil, inFile, "", err
	}

	// check the first byte...
	if header[0] != 1 {
		return nil, inFile, "", fmt.Errorf("%s Corrupted file.", fn)
	}

	reader := &cipher.StreamReader{S: spritz.NewStream(pw, header[1:]), R: inFile}

	encheader := make([]byte, 9)
	if _, err = io.ReadFull(reader, encheader); err != nil {
		return reader, inFile, "", err
	}

	check := spritz.Sum(32, encheader[0:4])
	if !bytes.Equal(check, encheader[4:8]) {
		return reader, inFile, "", fmt.Errorf("%s Bad password or corrupted file!", fn)
	}

	// input looks good, so set up the output
	// get the filename, if any, from the file:
	decn := ""
	if encheader[8] > 0 {
		decnBytes := make([]byte, encheader[8])
		if _, err = io.ReadFull(reader, decnBytes); err != nil {
			return reader, inFile, "", err
		}
		decn = string(decnBytes)
	}

	return reader, inFile, decn, nil
}

func check(pw, fn string) error {
	var err error

	_, fl, decn, err := initDecryption(pw, fn)
	if fl != nil {
		defer fl.Close()
	}
	if err != nil {
		return err
	}

	fmt.Printf("%s: good file. Unencrypted name is <%s>\n", fn, decn)
	return nil
}

func decrypt(pw, fn string) error {

	var outFile *os.File
	var err error

	reader, fl, decn, err := initDecryption(pw, fn)
	if fl != nil {
		defer fl.Close()
	}
	if err != nil {
		return err
	}

	if fn == "-" {
		outFile = os.Stdout
	} else {
		if len(decn) == 0 {
			if strings.HasSuffix(fn, ".spritz") {
				decn = fn[:len(fn)-7]
			} else {
				decn = fn + ".decrypted"
			}
		} else {
			decn = filepath.Join(filepath.Dir(fn), decn)
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

func cryptMain() {
	cmdSet := flag.NewFlagSet("crypt", flag.ExitOnError)
	cmdSet.StringVar(&pw, "password", "", "the password to use for encryption/decryption")
	cmdSet.StringVar(&pw, "p", "", "shorthand for --password")
	cmdSet.StringVar(&outdir, "odir", "", "the output directory")
	cmdSet.StringVar(&outdir, "o", "", "shorthand for --odir")
	cmdSet.IntVar(&jobs, "jobs", 2, "number of concurrent files to work on")
	cmdSet.IntVar(&jobs, "j", 2, "shorthand for --jobs")
	cmdSet.BoolVar(&decryptMode, "d", false, "shorthand for --decrypt")
	cmdSet.BoolVar(&decryptMode, "decrypt", false, "decrypt the files")
	cmdSet.BoolVar(&checkMode, "c", false, "shorthand for --check")
	cmdSet.BoolVar(&checkMode, "check", false, "check the file/pw combination")
	cmdSet.Parse(os.Args[2:])

	if len(pw) == 0 {
		var err error

		var times = 2
		if decryptMode || checkMode {
			times = 1
		}

		pw, err = password.Read("Password: ", times)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
			os.Exit(1)
		}
	}

	if len(pw) == 0 {
		fmt.Fprintf(os.Stderr, "Missing password.\n")
		cmdSet.Usage()
		os.Exit(2)
	}

	// select the encryption/decryption function
	var process func(string, string) error
	switch {
	case checkMode:
		process = check
	case decryptMode:
		process = decrypt
	default:
		process = encrypt
	}

	// no filenames means act as a filter
	files := cmdSet.Args()
	if len(files) == 0 {
		files = append(files, "-")
	}

	var limiter = make(chan struct{}, jobs)
	var wg sync.WaitGroup
	wg.Add(len(files))

	var hadErrors bool // is bool change atomic? surely so... need to check RWT

	for _, fname := range files {
		go func(fname string) {
			defer wg.Done()

			limiter <- struct{}{}
			if err := process(pw, fname); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
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
