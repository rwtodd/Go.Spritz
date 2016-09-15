// A rudimentary encryptor-decryptor.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rwtodd/spritz-go"
	"github.com/rwtodd/terminal-go/password"
)

// Command-line switches ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
var opw string // the password for the existing file
var npw string // the password for the new file
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

func repassMain() {
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

	// no filenames means act as a filter
	files := cmdSet.Args()
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "No files given!")
		cmdSet.Usage()
		os.Exit(1)
	}

	limiter = make(chan struct{}, jobs)
	wg.Add(len(files))

	for _, fname := range files {
		go func(fname string) {
			defer wg.Done()

			limiter <- struct{}{}
			if err := spritz.RePasswd(opw, npw, fname); err != nil {
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
