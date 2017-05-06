// A rudimentary encryptor-decryptor.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rwtodd/Go.AppUtil/password"
	"github.com/rwtodd/Go.Spritz/spritz"
)

// Command-line switches ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
var opw string // the password for the existing file
var npw string // the password for the new file
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

func repassRoutine(input chan string, errs chan uint64) {
	var errCount uint64
	for fname := range input {
		if err := spritz.RePasswd(opw, npw, fname); err != nil {
			fmt.Fprintf(os.Stderr, "Repass %s: %v\n", fname, err)
			errCount++
		}
	}
	errs <- errCount
}

func repassMain() {
	var errCount uint64

	cmdSet := flag.NewFlagSet("repass", flag.ExitOnError)
	cmdSet.StringVar(&npw, "newpass", "", "the password to use for encryption")
	cmdSet.StringVar(&npw, "np", "", "shorthand for --newpass")
	cmdSet.StringVar(&opw, "oldpass", "", "the password to use for decryption")
	cmdSet.StringVar(&opw, "op", "", "shorthand for --oldpass")
	cmdSet.IntVar(&jobs, "jobs", 2, "number of concurrent files to work on")
	cmdSet.IntVar(&jobs, "j", 2, "shorthand for --jobs")
	cmdSet.Parse(os.Args[2:])

	if len(opw) == 0 {
		var err error

		opw, err = password.Read("Old Password: ", 1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
			os.Exit(1)
		}
	}

	if len(npw) == 0 {
		var err error

		npw, err = password.Read("New Password: ", 2)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
			os.Exit(1)
		}
	}

	// for repass, you must have a file
	files := cmdSet.Args()
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "No files given!")
		cmdSet.Usage()
		os.Exit(1)
	}

	// start up the worker goroutines and feed them
	input, errs := make(chan string, jobs), make(chan uint64, jobs)
	for idx := 0; idx < jobs; idx++ {
		go repassRoutine(input, errs)
	}

	for _, fname := range files {
		input <- fname
	}

	// close the input channel and collect the reported error counts
	close(input)
	for idx := 0; idx < jobs; idx++ {
		errCount += <-errs
	}
	if errCount > 0 {
		os.Exit(1)
	}
}
