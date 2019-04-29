# checkpassword

This command checks passwords against [haveibeenpwned.com's alphbetized, SHA1 password list](~/pwned-passwords-sha1-ordered-by-hash-v4.txt).

The latest password list as of writing is 23GB uncompressed, so a naive text search can be slow and memory-intensive.
This program mmaps the file and binary searches over it.
This approach is fast and has minor memory usage.

```
go get github.com/jbowens/checkpassword
go install github.com/jbowens/checkpassword
checkpassword -file ~/pwned-passwords-sha1-ordered-by-hash-v4.txt "password"
```
