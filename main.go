// Package main provides the entry point for the MPC application
package main

import (
	"fmt"
	"os"
)

func main() {
	// Redirect to the actual CLI implementation
	fmt.Println("Please use one of the following commands:")
	fmt.Println("  go run ./cmd/lux-mpc          - Run the MPC node")
	fmt.Println("  go run ./cmd/lux-mpc-cli      - Run the MPC CLI")
	os.Exit(0)
}
