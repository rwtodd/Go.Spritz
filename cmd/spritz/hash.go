package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/rwtodd/Go.Spritz/spritz"
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

func hashRoutine(input chan string, errs chan uint64) {
	var errCount uint64
	for fname := range input {
		if err := hash(fname); err != nil {
			fmt.Fprintf(os.Stderr, "Hashing %s: %v\n", fname, err)
			errCount++
		}
	}
	errs <- errCount
}

func hashMain() {
	var errCount uint64

	cmdSet := flag.NewFlagSet("hash", flag.ExitOnError)
	cmdSet.IntVar(&bitSize, "size", 256, "size of the hash in bits")
	cmdSet.IntVar(&bitSize, "s", 256, "shorthand for --size")
	cmdSet.BoolVar(&asHex, "hex", false, "output hex instead of base64")
	cmdSet.BoolVar(&asHex, "h", false, "shorthand for --hex")
	cmdSet.IntVar(&jobs, "jobs", 8, "number of concurrent hashes to compute")
	cmdSet.IntVar(&jobs, "j", 8, "shorthand for --jobs")
	cmdSet.Parse(os.Args[2:])

	input, errs := make(chan string, jobs), make(chan uint64, jobs)
	for idx := 0; idx < jobs; idx++ {
		go hashRoutine(input, errs)
	}

	args := cmdSet.Args()

	// act as a filter with no args...
	if len(args) == 0 {
		input <- "-"
	}

	// process any filenames we were given
	for _, fname := range args {
		err := filepath.Walk(fname, func(fname string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if fi.Mode().IsRegular() {
				input <- fname
			}
			return nil
		})

		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			errCount++
		}
	}

	// close the input channel and collect the worker goroutines' error counts.
	close(input)
	for idx := 0; idx < jobs; idx++ {
		errCount += <-errs
	}
	if errCount > 0 {
		os.Exit(1)
	}
}
