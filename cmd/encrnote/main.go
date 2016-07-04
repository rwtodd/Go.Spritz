package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/fcgi"
	"os"

	"github.com/rwtodd/spritz-go"
)

var local = flag.String("local", "", "serve as webserver on this localhost port (e.g., 8000)")
var fname = flag.String("input", "", "use the given input file")
var pw string // the password of the loaded file

func main() {
	flag.Parse()
	if len(*fname) == 0 {
		log.Fatal("Must give an -input filename!")
		return
	}

	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/encr.css", cssHandler)
	http.HandleFunc("/load", loadHandler)
	http.HandleFunc("/save", saveHandler)

	var err error
	if *local != "" {
		err = http.ListenAndServe("localhost:"+*local, nil)
	} else {
		err = fcgi.Serve(nil, nil)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func cssHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "encr.css")
}

type response struct {
	OK          bool
	Text        string
	ErrorDetail string
}

func writeErr(err error, w http.ResponseWriter) {
	respjson, _ := json.Marshal(&response{false, "", err.Error()})
	w.Write(respjson)
	log.Print(err)
}

func loadHandler(w http.ResponseWriter, r *http.Request) {
	log.Print("LOAD")
	pw = "" // only set the global pw on success

	pwbytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		writeErr(err, w)
		return
	}

	locpw := string(pwbytes)
	src, err := os.Open(*fname)
	if err != nil {
		writeErr(err, w)
		return
	}
	defer src.Close()

	decrypted, _, err := spritz.WrapReader(src, locpw)
	if err != nil {
		writeErr(err, w)
		return
	}

	docbytes, err := ioutil.ReadAll(decrypted)
	if err != nil {
		writeErr(err, w)
		return
	}

	respjson, err := json.Marshal(&response{true, string(docbytes), ""})
	if err != nil {
		writeErr(err, w)
		return
	}

	pw = locpw // all ok, save the pw
	w.Write(respjson)
}

func saveHandler(w http.ResponseWriter, r *http.Request) {
	log.Print("SAVE")
	if len(pw) == 0 {
		writeErr(fmt.Errorf("File not properly loaded"), w)
		return
	}

	docbytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		writeErr(err, w)
		return
	}

	if err = os.Rename(*fname, (*fname)+".bak"); err != nil {
		writeErr(err, w)
		return
	}

	outFile, err := os.OpenFile(*fname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		writeErr(err, w)
		return
	}
	defer outFile.Close()

	writer, err := spritz.WrapWriter(outFile, pw, "")
	if err != nil {
		writeErr(err, w)
		return
	}

	if _, err = writer.Write(docbytes); err != nil {
		writeErr(err, w)
		return
	}

	respjson, err := json.Marshal(&response{true, "", ""})
	if err != nil {
		writeErr(err, w)
		return
	}
	w.Write(respjson)
}
