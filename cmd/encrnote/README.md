# EncrNote Tool

This is a Go version of the JEncrNotes java tool in my 
[multi-language spritz repository][1].  It presents a
simple local webpage that lets you decode, edit, and
encode an encrypted note. 

The tool stores a '.bak' file of the input upon saving,
just in case!

It's run like this (from the directory with the index and css
files):

    encrnote -local 8001 -input mynote.spritz

[1]: https://github.com/rwtodd/spritz_cipher
