// A rudimentary encryptor-decryptor.

package main

import (
	"compress/zlib"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rwtodd/spritz-go"
	"github.com/rwtodd/terminal-go/password"
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

// chext changes the extension of a file name
func chext(in, ext string) string {
	dir, base := filepath.Dir(in), filepath.Base(in)
	idx := strings.LastIndex(base, ".")
	if idx > 0 {
		base = base[0:idx]
	}

	return filepath.Join(dir, base+ext)
}

func encrypt(pw, fn string) error {
	var err error

	var inFile, outFile *os.File
	var embeddedName string
	if fn == "-" {
		inFile, outFile = os.Stdin, os.Stdout
	} else {
		embeddedName = filepath.Base(fn)

		encn := odir(chext(fn, ".dat"))
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

	writer, err := spritz.WrapWriter(outFile, pw, embeddedName)
	if err != nil {
		return err
	}

        compressed := zlib.NewWriter(writer)
	_, err = io.Copy(compressed, inFile)
        compressed.Close() // flush everything not yet written...

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

	rdr, decn, err := spritz.WrapReader(inFile, pw)
	return rdr, inFile, decn, err
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

        decomp, err := zlib.NewReader(reader)
        if err != nil {
		return err
        }

	_, err = io.Copy(outFile, decomp)
        decomp.Close()
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

	limiter = make(chan struct{}, jobs)
	wg.Add(len(files))

	for _, fname := range files {
		go func(fname string) {
			defer wg.Done()

			limiter <- struct{}{}
			if err := process(pw, fname); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				incErr()
			}
			<-limiter
		}(fname)
	}

	wg.Wait()

	if errCount > 0 {
		os.Exit(1)
	}
}
