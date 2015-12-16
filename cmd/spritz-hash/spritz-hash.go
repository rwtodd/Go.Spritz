package main

import (
	"flag"
	"fmt"
	"github.com/waywardcode/crypto/spritz"
	"io"
	"os"
)

var size = flag.Int("size", 256, "size of the hash in bits")

func printHash(hash []byte) {
	for _, v := range hash {
		fmt.Printf("%02x", v)
	}
}

func main() {
	flag.Parse()
	for _, fname := range flag.Args() {
		fmt.Printf("%s: ", fname)
		infile, _ := os.Open(fname)
		shash := spritz.NewHash(*size)
		_, err := io.Copy(shash, infile)
		infile.Close()
		if err == nil {
			printHash(shash.Sum(nil))
		} else {
			fmt.Print(err.Error())
		}
		fmt.Println("")
	}
}
