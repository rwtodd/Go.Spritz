package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/waywardcode/crypto/spritz"
)

var bitSize = flag.Int("size", 256, "size of the hash in bits")

func runHash(fname string) {
	byteSize := (*bitSize + 7) / 8

	infile, _ := os.Open(fname)
	shash := spritz.NewHash(*bitSize)
	_, err := io.Copy(shash, infile)
	infile.Close()

	if err == nil {
		computed := shash.Sum(make([]byte, 0, byteSize))
		fmt.Printf("%s: %x\n", fname, computed)
	} else {
		fmt.Printf("%s: %s\n", fname, err.Error())
	}

}

// runFiles creates a goroutine to hash a file, or recurses on
// directories.
func runFiles(fi os.FileInfo,
	path string,
	limiter chan struct{},
	wg *sync.WaitGroup) {
	if fi.IsDir() {

		allfiles, err := ioutil.ReadDir(path)
		if err != nil {
			fmt.Printf("%s: unable to read directory! %s\n",
				path, err.Error())
			return
		}

		for _, fi := range allfiles {
			newdir := filepath.Join(path, fi.Name())
			runFiles(fi, newdir, limiter, wg)
		}

	} else {

		wg.Add(1)
		go func(fname string) {
			defer wg.Done()

			limiter <- struct{}{} // take a slot
			runHash(fname)
			<-limiter // release the slot

		}(path)

	}
}

func main() {
	flag.Parse()

	// work on up to 8 files at a time
	limiter := make(chan struct{}, 8)

	// we will wait until all the goroutines are done...
	var wg sync.WaitGroup
	for _, fname := range flag.Args() {
		fi, err := os.Stat(fname)
		if err == nil {
			runFiles(fi, fname, limiter, &wg)
		} else {
			fmt.Printf("%s: unable to stat! %s\n", fname, err.Error())
		}
	}

	wg.Wait() // sit here until everyting is reported
}
