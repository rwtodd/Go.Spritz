package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	spritz "github.com/waywardcode/spritz_go"
)

var bitSize int
var jobs int

func init() {
	flag.IntVar(&bitSize, "size", 256, "size of the hash in bits")
	flag.IntVar(&bitSize, "s", 256, "shorthand for --size")
	flag.IntVar(&jobs, "jobs", 8, "number of concurrent hashes to compute")
	flag.IntVar(&jobs, "j", 8, "shorthand for --jobs")
}

var limiter chan struct{} // limits the number of files we can work on at once
var wg sync.WaitGroup     // this is how we'll make sure all goroutines are done

// hash performs the actual hash, and prints out the result.
func hash(fname string) {
	byteSize := (bitSize + 7) / 8

	infile, _ := os.Open(fname)
	shash := spritz.NewHash(bitSize)
	_, err := io.Copy(shash, infile)
	infile.Close()

	if err == nil {
		computed := shash.Sum(make([]byte, 0, byteSize))
		fmt.Printf("%s: %x\n", fname, computed)
	} else {
		fmt.Printf("%s: %s\n", fname, err.Error())
	}

}

// hashFiles creates a goroutine to hash files
func hashFiles(fname string, fi os.FileInfo, err error) error {
	if err != nil {
		fmt.Printf("%s: problem! %s\n", fname, err.Error())
		return nil // just skip problem files
	}

	if fi.Mode().IsRegular() {
		wg.Add(1)
		go func() {
			defer wg.Done()

			limiter <- struct{}{} // take a slot
			hash(fname)
			<-limiter // release the slot
		}()
	}

	return nil
}

func main() {
	flag.Parse()
	limiter = make(chan struct{}, jobs)

	for _, fname := range flag.Args() {
		var err = filepath.Walk(fname, hashFiles)
		if err != nil {
			fmt.Printf("%s: unable to stat! %s\n", fname, err.Error())
		}
	}

	wg.Wait() // sit here until everyting is reported
}
