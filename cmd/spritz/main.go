package main

import (
	"fmt"
	"os"

	"github.com/rwtodd/apputil/cmdline"
)

// ----------------------
// global command args
// ----------------------
var jobs int

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:  spritz (hash|crypt|repass) [args...]")
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
