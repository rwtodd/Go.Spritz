package main

import (
	"flag"
	"fmt"
	"github.com/waywardcode/crypto/spritz"
	"io"
	"os"
	"sync"
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

func main() {
	flag.Parse()
	flist := flag.Args()

	// work on up to 8 files at a time
	limiter := make(chan struct{}, 8)

	// we will wait until all the goroutines are done...
	var wg sync.WaitGroup
	wg.Add(len(flist))

	for _, fname := range flist {
		go func(fname string) {
			defer wg.Done()

			limiter <- struct{}{} // take a slot
			runHash(fname)
			<-limiter // release the slot
		}(fname)
	}

	wg.Wait() // sit here until everyting is reported
}
