package main

// this is just a little program to re-encrypt a file into the newest
// encryption version available.

// meant to be run with `go run` after setting up the pasword... just a 
// quick-and-dirty utility script

import (
 "compress/zlib"
 "os"
 "io"
 "fmt"
 
 "github.com/rwtodd/apputil/cmdline"
 "github.com/rwtodd/apputil/errs"
 "github.com/rwtodd/spritz-go"
)

const (
  pw = "PUT PASSWORD HERE"
)


func recode(fn string) error {
   var err error

   bak := fn + ".bak"
   if err = os.Rename(fn, bak); err != nil {
       return errs.Wrap("Renaming step", err)
   }

   var inFile, outFile *os.File
   if inFile, err = os.Open(bak); err != nil {
      return errs.Wrap("Opening src", err)
   }
   defer inFile.Close()
   
   if outFile, err = os.OpenFile(fn,
      os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
      0666) ; err != nil {
      return errs.Wrap("Opening dest", err)
   }
   defer outFile.Close()

   reader, embedName, err1 := spritz.WrapReader(inFile, pw)
   decomp, err := zlib.NewReader(reader)
   if err != nil { return err }

   writer, err2            := spritz.WrapWriter(outFile, pw, embedName)
   compressed,_            := zlib.NewWriterLevel(writer, zlib.BestCompression)
   _, err3                 := io.Copy(compressed, decomp)
   compressed.Close() // flush everything not yet written...
   
   return errs.First("Performing re-encryption", err1, err2, err3)
   
}

func main() {
  cmdline.GlobArgs()
  args := os.Args[1:]

  for _, fname := range args {
	  fmt.Println(fname)
	  if err := recode(fname); err != nil {
	     fmt.Fprintf(os.Stderr, "%v\n", err)
 	  }
  }
  
}
