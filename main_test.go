package main

import (
	"os"
	"testing"
)

func BenchmarkCheckPassword(b *testing.B) {
	f := os.Getenv("PASSWORDS_FILE")
	if f == "" {
		b.Skip("$PASSWORDS_FILE is unset")
	}
	for i := 0; i < b.N; i++ {
		_, err := checkPasswords(f, []string{`password`})
		if err != nil {
			b.Fatal(err)
		}
	}
}
