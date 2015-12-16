package main

import (
	"fmt"
	"github.com/waywardcode/crypto/spritz"
	"io"
	"os"
)

func printHash(hash []byte) {
	for _, v := range hash {
		fmt.Printf("%02x", v)
	}
}

func main() {
	for _, fname := range os.Args[1:] {
		fmt.Printf("%s: ", fname)
		infile, _ := os.Open(fname)
		shash := spritz.NewHash(256)
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
