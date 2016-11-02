package main

import (
	"fmt"
	"os"
	"sync"

	"github.com/rwtodd/apputil/cmdline"
)

// ----------------------
// global command args
// ----------------------
var jobs int

// -------------------
// global error count
// -------------------
var errCount int
var errMutex sync.Mutex

func incErr() {
	errMutex.Lock()
	errCount++
	errMutex.Unlock()
}

// -------------------------------
// global limiter for parallelism
// -------------------------------
var limiter chan struct{} // limits the number of files we can work on at once
var wg sync.WaitGroup     // this is how we'll make sure all goroutines are done

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:  spritz (hash|crypt) [args...]")
	fmt.Fprintln(os.Stderr, "Commands:  hash   compute the hash of inputs")
	fmt.Fprintln(os.Stderr, "           crypt  encrypt or decrypt inputs")
	fmt.Fprintln(os.Stderr, "           repass change password on files")
	fmt.Fprintln(os.Stderr, "  Give '-h' arg for further help on a command")
	os.Exit(2)
}

func main() {
	cmdline.GlobArgs()

	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "hash":
		hashMain()
	case "crypt":
		cryptMain()
	case "repass":
		repassMain()
	default:
		usage()
	}
}
