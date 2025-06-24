package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %s <password>\n", os.Args[0])
		os.Exit(1)
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(os.Args[1]), 10)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error generating hash: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(passwordHash))
}
