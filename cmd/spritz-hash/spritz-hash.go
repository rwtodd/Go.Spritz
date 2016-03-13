package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"go.waywardcode.com/spritz"
)

// Cmdline arguments ~~~~~~~~~~~~~~~~~~~~~~
var bitSize int
var jobs int

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

// Global error count ~~~~~~~~~~~~~~~~~~~~~
var errCount int
var errMutex sync.Mutex

func incErr() {
	errMutex.Lock()
	errCount++
	errMutex.Unlock()

}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

func init() {
	flag.IntVar(&bitSize, "size", 256, "size of the hash in bits")
	flag.IntVar(&bitSize, "s", 256, "shorthand for --size")
	flag.IntVar(&jobs, "jobs", 8, "number of concurrent hashes to compute")
	flag.IntVar(&jobs, "j", 8, "shorthand for --jobs")
}

var limiter chan struct{} // limits the number of files we can work on at once
var wg sync.WaitGroup     // this is how we'll make sure all goroutines are done

// hash performs the actual hash, and prints out the result.
func hash(fname string) (err error) {
	byteSize := (bitSize + 7) / 8
	var inFile *os.File
	var outFormat string // how we will format the output

	if fname == "-" {
		inFile = os.Stdin
		outFormat = "%s%x\n"
		fname = ""
	} else {
		if inFile, err = os.Open(fname); err != nil {
			return
		}
		defer inFile.Close()
		outFormat = "%s: %x\n"
	}

	shash := spritz.NewHash(bitSize)
	if _, err = io.Copy(shash, inFile); err != nil {
		return
	}

	computed := shash.Sum(make([]byte, 0, byteSize))
	fmt.Printf(outFormat, fname, computed)
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

func main() {
	flag.Parse()
	limiter = make(chan struct{}, jobs)

	args := flag.Args()

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
