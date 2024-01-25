package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func AVScan() {
	// Create or open the file to write the hashes
	file, err := os.Create("av-hash.txt")
	if err != nil {
		log.Fatalf("Failed to create file: %v", err)
	}
	defer file.Close()

	err = filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
        if os.IsPermission(err) {
        log.Printf("Skipping directory do to permission error: %s", path)

        return filepath.SkipDir
      }
        return err
    }
		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Read the content of the file
		content, err := os.ReadFile(path)
		if err != nil {
			log.Printf("Error reading file %s: %v", path, err)
			return nil
		}

		// Create a new SHA256 hash object
		hasher := sha256.New()
		hasher.Write(content)
		hash := hasher.Sum(nil)

		// Print the hash to the console
		fmt.Printf("File: %s, SHA256: %x\n", info.Name(), hash)

		// Write the hash to the file
		_, err = file.WriteString(fmt.Sprintf("File: %s, SHA256: %x\n", info.Name(), hash))
		if err != nil {
			log.Printf("Failed to write to file: %v", err)
			return err
		}

		return nil
	})

	if err != nil {
		log.Printf("Error walking the path: %v", err)
	}
}

func main() {
	AVScan()
}

