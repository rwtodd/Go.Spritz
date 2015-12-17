package main

import (
	"flag"
	"fmt"
	"github.com/waywardcode/crypto/spritz"
	"io"
	"os"
)

var bitSize = flag.Int("size", 256, "size of the hash in bits")

func main() {
	flag.Parse()
	byteSize := (*bitSize + 7) / 8
	for _, fname := range flag.Args() {
		fmt.Printf("%s: ", fname)
		infile, _ := os.Open(fname)
		shash := spritz.NewHash(*bitSize)
		_, err := io.Copy(shash, infile)
		infile.Close()
		if err == nil {
			computed := shash.Sum(make([]byte, 0, byteSize))
			fmt.Printf("%x\n", computed)
		} else {
			fmt.Println(err.Error())
		}
	}
}
