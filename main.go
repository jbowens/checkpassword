// Command checkpassword checks passwords against a SHA1
// password list.
//
// It was built to be used with the password list from
// https://haveibeenpwned.com/Passwords. As such, it
// expects the password list to consist of alphabetized,
// capitalized, hex-encoded SHA1 hashes. It expects
// each hash to be on its own line with a colon
// delineating the hash from the number of occurrences
// in breaches.
//
// For example,
//
//    000000005AD76BD555C1D6D771DE417A4B87E4B4:4
//    00000000A8DAE4228F821FB418F59826079BF368:2
//    00000000DD7F2A1C68A35673713783CA390C9E93:630
//
// The checkpassword command mmaps the password list and
// performs binary search over the mmaped file.
package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"

	"golang.org/x/exp/mmap"
)

var (
	newline = []byte("\n")
	colon   = []byte(":")
)

func main() {
	var file string
	flag.StringVar(&file, "file", "", "path to a sorted SHA1 password list")
	flag.Parse()

	m, err := checkPasswords(file, flag.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for _, pw := range flag.Args() {
		if v, ok := m[pw]; ok {
			fmt.Printf("%q has been leaked %d times.\n", pw, v)
		} else {
			fmt.Printf("%q is not in this dataset.\n", pw)
		}
	}

	// If one of the tested passwords was leaked, set
	// a non-zero exit code so that the CLI may be
	// used in bash scripts.
	if len(m) > 0 {
		os.Exit(2)
	}
}

func checkPasswords(file string, passwords []string) (map[string]int, error) {
	// Hash each othe password to check, and store
	// a map from the hash to the password.
	checkHashes := make(map[string]string, len(passwords))
	for _, pw := range passwords {
		digest := sha1.Sum([]byte(pw))
		hexHash := fmt.Sprintf("%X", digest[:])
		checkHashes[hexHash] = pw
	}

	// Retrieve the size of the password list file,
	// and then mmap it.
	fi, err := os.Stat(file)
	if err != nil {
		return nil, err
	}
	readerAt, err := mmap.Open(file)
	if err != nil {
		return nil, err
	}
	len := fi.Size()

	m := map[string]int{}
	var buf [128]byte
	for h, pw := range checkHashes {
		hashBytes := []byte(h)
		i, err := search(int(len), readerAt, buf[:], hashBytes)
		if err != nil {
			return nil, err
		}
		entryHash, count, err := entryAt(readerAt, i, buf[:])
		if err != nil {
			return nil, err
		}

		if bytes.Equal(entryHash, hashBytes) {
			v, err := strconv.Atoi(string(count))
			if err != nil {
				return nil, err
			}
			m[pw] = v
		}
	}
	return m, readerAt.Close()
}

func search(size int, r io.ReaderAt, buf []byte, query []byte) (int, error) {
	var reterr error
	return sort.Search(size, func(i int) bool {
		hash, _, err := entryAt(r, i, buf)
		if err != nil {
			reterr = err
		}
		return bytes.Compare(query, hash) <= 0
	}), reterr
}

func entryAt(r io.ReaderAt, i int, buf []byte) (hash, count []byte, err error) {
	n, err := r.ReadAt(buf, int64(i))
	if err != nil && err != io.EOF {
		return nil, nil, err
	}
	buf = buf[:n]

	line := buf
	if bytes.Index(buf, colon) != hex.EncodedLen(sha1.Size) {
		line = buf[bytes.Index(buf, newline)+1:]
	}
	line = line[:bytes.Index(line, newline)]

	pieces := bytes.Split(line, colon)
	hash, count = pieces[0], bytes.TrimSpace(pieces[1])
	return hash, count, nil
}
