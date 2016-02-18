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
	"strings"
	"sync"

	spritz "github.com/waywardcode/spritz_go"
)

var pw string
var jobs int

func init() {
	flag.StringVar(&pw, "password", "", "the password to use for encryption/decryption")
	flag.StringVar(&pw, "p", "", "shorthand for --password")
	flag.IntVar(&jobs, "jobs", 8, "number of concurrent files to work on")
	flag.IntVar(&jobs, "j", 8, "shorthand for --jobs")
}

func encrypt(pw, fn string) {
	encn := fn + ".spritz"
	fmt.Printf("%s -> %s\n", fn, encn)

	// we need random data for the IV and authentication token
	var rdata = make([]byte, 8)
	_, err := rand.Read(rdata)
	if err != nil {
		fmt.Printf("%s Couldn't generate random data! %s\n", fn, err.Error())
		return
	}

	inFile, err := os.Open(fn)
	if err != nil {
		fmt.Printf("%s Couldn't open input file! %s\n", fn, err.Error())
		return
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(encn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Printf("%s Couldn't open output file! %s\n", fn, err.Error())
		return
	}
	defer outFile.Close()

	outFile.Write(rdata[:4]) // write the IV unencrypted!

	writer := &cipher.StreamWriter{S: spritz.NewStream(pw, rdata[:4]), W: outFile}
	_, err = writer.Write(rdata[4:])                   // write the authentication token
	_, err2 := writer.Write(spritz.Sum(32, rdata[4:])) // write the hash of the token
	if err != nil || err2 != nil {
		fmt.Printf("%s Couldn't write the authentication token!\n", fn)
		return
	}

	_, err = io.Copy(writer, inFile)
	if err != nil {
		fmt.Printf("%s Couldn't write output file! %s\n", fn, err.Error())
		return
	}
}

func decrypt(pw, fn string) {
	decn := fn[:len(fn)-7] // strip off the ".spritz"
	fmt.Printf("%s -> %s\n", fn, decn)

	inFile, err := os.Open(fn)
	if err != nil {
		fmt.Printf("%s Couldn't open input file! %s\n", fn, err.Error())
		return
	}
	defer inFile.Close()

	iv := make([]byte, 4)
	_, err = io.ReadFull(inFile, iv)
	if err != nil {
		fmt.Printf("%s Couldn't read the IV! %s\n", fn, err.Error())
		return
	}

	reader := &cipher.StreamReader{S: spritz.NewStream(pw, iv), R: inFile}

	authdata := make([]byte, 8)
	_, err = io.ReadFull(reader, authdata) // read the authentication token
	if err != nil {
		fmt.Printf("%s Couldn't read authentication data! %s\n", fn, err.Error())
		return
	}

	check := spritz.Sum(32, authdata[:4])
	if !bytes.Equal(check, authdata[4:]) {
		fmt.Printf("%s Bad password or corrupted file!\n", fn)
		return
	}

	outFile, err := os.OpenFile(decn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Printf("%s Couldn't open output file! %s\n", fn, err.Error())
		return
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, reader)
	if err != nil {
		fmt.Printf("%s Couldn't write output file! %s\n", fn, err.Error())
		return
	}
}

func main() {
	flag.Parse()

	if len(pw) == 0 {
		flag.Usage()
	}

	var limiter = make(chan struct{}, jobs)
	var wg sync.WaitGroup
	wg.Add(len(flag.Args()))

	for _, fname := range flag.Args() {
		go func(fname string) {
			defer wg.Done()

			limiter <- struct{}{}
			if strings.HasSuffix(fname, ".spritz") {
				decrypt(pw, fname)
			} else {
				encrypt(pw, fname)
			}
			<-limiter
		}(fname)
	}

	wg.Wait()
}
