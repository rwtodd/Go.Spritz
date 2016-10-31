package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/rwtodd/spritz-go"
)

// Cmdline arguments ~~~~~~~~~~~~~~~~~~~~~~
var bitSize int
var asHex bool

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

// hash performs the actual hash, and prints out the result.
func hash(fname string) (err error) {
	byteSize := (bitSize + 7) / 8
	var inFile *os.File

	if fname == "-" {
		inFile = os.Stdin
		fname = ""
	} else {
		if inFile, err = os.Open(fname); err != nil {
			return
		}
		defer inFile.Close()
	}

	shash := spritz.NewHash(bitSize)
	if _, err = io.Copy(shash, inFile); err != nil {
		return
	}

	computed := shash.Sum(make([]byte, 0, byteSize))
	if asHex {
		fmt.Printf("%s: %x\n", fname, computed)
	} else {
		fmt.Printf("%s: %s\n", fname, base64.StdEncoding.EncodeToString(computed))
	}
	return
}

// hashFiles creates a goroutine to hash files
func hashFiles(fname string, fi os.FileInfo, err error) error {
	if err != nil {
		return err
	}

	if fi.Mode().IsRegular() {
		wg.Add(1)
		go func() {
			defer wg.Done()

			limiter <- struct{}{} // take a slot
			if err := hash(fname); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				incErr()
			}
			<-limiter // release the slot
		}()
	}

	return nil
}

func hashMain() {
	cmdSet := flag.NewFlagSet("hash", flag.ExitOnError)
	cmdSet.IntVar(&bitSize, "size", 256, "size of the hash in bits")
	cmdSet.IntVar(&bitSize, "s", 256, "shorthand for --size")
	cmdSet.BoolVar(&asHex, "hex", false, "output hex instead of base64")
	cmdSet.BoolVar(&asHex, "h", false, "shorthand for --hex")
	cmdSet.IntVar(&jobs, "jobs", 8, "number of concurrent hashes to compute")
	cmdSet.IntVar(&jobs, "j", 8, "shorthand for --jobs")
	cmdSet.Parse(os.Args[2:])
	limiter = make(chan struct{}, jobs)

	args := cmdSet.Args()

	// act as a filter with no args...
	if len(args) == 0 {
		if err := hash("-"); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			incErr()
		}
	}

	// process any filenames we were given
	for _, fname := range args {
		if err := filepath.Walk(fname, hashFiles); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			incErr()
		}
	}

	wg.Wait() // sit here until everyting is reported
	if errCount > 0 {
		os.Exit(1)
	}
}
