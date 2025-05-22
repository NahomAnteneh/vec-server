package main

import (
	"fmt"
	"os"

	"github.com/NahomAnteneh/vec-server/pkg/client"
)

func main() {
	fmt.Println("Vec Server Client Test")
	fmt.Println("======================")

	// Run the client tests
	client.RunTest()

	os.Exit(0)
}
