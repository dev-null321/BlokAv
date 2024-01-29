package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// AV Scan signature scan

func main() {
	ShowMenu()
}

func ShowMenu() {
	fmt.Println("[1] Connect to BlockAV (Initialize connection to the BlockAV network)")
	fmt.Println("[2] Run Quick Scan (Perform a quick scan of your system for known threats)")
	fmt.Println("[3] Run Behavioral Scan (Perform a behavioral analysis scan for potential threats)")
	fmt.Println("[4] Upload File To BlockAV (Contribute to the BlockAV network by uploading a file for analysis)")

	var choice int
	fmt.Scanln(&choice)

	switch choice {
	case 1:
		fmt.Println("Connecting to BlockAV...")

	case 2:
		fmt.Println("Running quick scan")
		scanPath := GetScanPath() // Retrieve the scan path
		AVScan(scanPath)          // Call AVScan with the correct argument

	case 3:
		fmt.Println("Running behavioral scan")
		scanPath := GetScanPath() // Retrieve the scan path
		AVScan(scanPath)          // Call AVScan with the correct argument
		RunLinuxScanner(scanPath)

	case 4:
		fmt.Println("Connecting to BlokAV")
		CreateNodes()
	}

	fmt.Printf("\n")

}

func GetScanPath() string {
	var userPath string

	fmt.Print("Enter the directory to scan (press Enter for current directory): ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		userPath = scanner.Text()
	}

	userPath = strings.TrimSpace(userPath)

	if userPath == "" {
		currentDir, err := os.Getwd()
		if err != nil {
			fmt.Println("Error getting the current working directory:", err)
			return ""
		}

		return currentDir
	}

	// Check if the entered path exists
	_, err := os.Stat(userPath)
	if err != nil {
		fmt.Println("Error:", err)
		return ""
	}

	return userPath
}

func AVScan(scanPath string) {
	// Create or open the file to write the hashes
	file, err := os.Create("av-hash.txt")
	if err != nil {
		log.Fatalf("Failed to create file: %v", err)
	}
	defer file.Close()

	// Open the local file
	localFilePath := "/Users/marq/Projects/blockav/mal-sha256.txt"

	// Read the content of the local file
	hashes, err := ioutil.ReadFile(localFilePath)
	if err != nil {
		log.Printf("Failed to read local file: %v", err)
		return
	}

	// Split the hash list into individual hashes
	hashList := strings.Fields(string(hashes))

	err = filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				log.Printf("Skipping directory due to permission error: %s", path)
				return filepath.SkipDir
			}
			log.Printf("Error walking the path: %v", err)
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

		for _, hashListEntry := range hashList {
			if hashListEntry == fmt.Sprintf("SHA256:%x", hash) {
				// Terminate matching process based on the OS
				// Terminate matching process based on the OS
				if runtime.GOOS == "linux" {
					err = TerminateLinuxProcess(info)
				} else if runtime.GOOS == "windows" {
					err = TerminateWindowsProcess(info)
				}

				if err != nil {
					log.Printf("Failed to terminate process: %v", err)
				} else {
					log.Printf("Terminated process %s (PID: %d)", info.Name(), os.Getpid())
				}
			}
		}

		return nil
	})

	if err != nil {
		log.Printf("Error walking the path: %v", err)
	}
}

// Terminate process on Linux
func TerminateLinuxProcess(info os.FileInfo) error {
	processName := info.Name() // Assuming processName is the name of the process
	cmd := exec.Command("pkill", "-f", processName)
	return cmd.Run()
}

// Terminate process on Windows
func TerminateWindowsProcess(info os.FileInfo) error {
	cmd := exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprint(os.Getpid()))
	return cmd.Run()
}

//LINUX SCAN

func RunLinuxScanner(directory string) {
	TmpfsSandbox(directory)
	IntensiveScan(directory)
}

// TmpfsSandbox creates a TMPFS sandbox to isolate a file
func TmpfsSandbox(directory string) {
	tmpfsDir := "/tmpfs"
	err := os.Mkdir(tmpfsDir, 0700)
	if err != nil {
		fmt.Println("Failed to create tmpfs directory:", err)
		os.Exit(1)
	}

	defer func() {
		if err := syscall.Unmount(tmpfsDir, 0); err != nil {
			fmt.Println("Failed to unmount tmpfs:", err)
		}
		if err := os.RemoveAll(tmpfsDir); err != nil {
			fmt.Println("Failed to remove tmpfs directory:", err)
		}
	}()

	fmt.Println("Sandbox created successfully for directory:", directory)
}

// IntensiveScan monitors the suspicious file for file writes and privilege escalation
func IntensiveScan(directory string) {
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println("Failed to scan files, please check log file in /tmp/")
			return nil
		}

		AnalyzeProcess(path)
		return nil
	})

	if err != nil {
		fmt.Println("Failed to scan files, please check log file in /tmp/")
	}
}

// AnalyzeProcess dynamically analyzes files in the given directory
func AnalyzeProcess(filePath string) {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("Error opening or creating the log file:", err)
		return
	}
	defer file.Close()

	logFile, err := os.OpenFile("/tmp/log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening or creating the log file:", err)
		return
	}
	defer logFile.Close()

	cmd := exec.Command(filePath) // Use the provided file path
	cmd.Stdout = io.MultiWriter(os.Stdout, logFile)
	cmd.Stderr = io.MultiWriter(os.Stderr, logFile)

	err = cmd.Run()
	if err != nil {
		fmt.Println("Error running the command:", err)
		return
	}

	MonitorPrivilegeEscalation()
}

// MonitorPrivilegeEscalation checks for privilege escalation
// MonitorPrivilegeEscalation checks for privilege escalation
func MonitorPrivilegeEscalation() {
	euid := syscall.Geteuid()
	if euid == 0 || GetSuid() {
		fmt.Println("Privilege escalation detected!")
		fmt.Println("Exiting application due to privilege escalation.")
		os.Exit(1)
	}
}

// GetSuid checks if the effective UID is not equal to the saved UID
func GetSuid() bool {
	euid := syscall.Geteuid()
	sid, _ := syscall.Getsid(0)
	return euid != sid
}

// TerminateMaliciousProcess terminates a process based on its path
func TerminateMaliciousProcess(filePath string) error {
	// Get the list of processes
	processes, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}

	// Iterate through processes
	for _, process := range processes {
		if process.IsDir() {
			pid := process.Name()

			// Check if the entry is a numeric directory (representing a process ID)
			if _, err := strconv.Atoi(pid); err == nil {
				// Check if the process executable matches the provided file path
				exePath := filepath.Join("/proc", pid, "exe")
				realPath, err := os.Readlink(exePath)
				if err != nil {
					continue
				}

				if strings.EqualFold(realPath, filePath) {
					// Terminate the process
					pidInt, err := strconv.Atoi(pid)
					if err != nil {
						return err
					}

					err = syscall.Kill(pidInt, syscall.SIGTERM)
					if err != nil {
						return err
					}

					fmt.Printf("Terminated malicious process with PID %d\n", pidInt)
					return nil
				}
			}
		}
	}

	return fmt.Errorf("Malicious process not found")
}

type Block struct {
	Index        int
	Timestamp    time.Time
	Hash         []byte
	PreviousHash []byte
}

type Blockchain struct {
	Blocks []Block
	mu     sync.Mutex
}

type Message struct {
	From    string
	Content string
	Block   Block
}

type Node struct {
	ID         string
	PublicKey  *ecdsa.PublicKey
	PrivateKey *ecdsa.PrivateKey
	Addresses  []string
	Blockchain Blockchain
}

func NewNode() (*Node, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	publicKey := &privKey.PublicKey

	node := &Node{
		ID:         generateRandomID(),
		PublicKey:  publicKey,
		PrivateKey: privKey,
		Addresses:  make([]string, 0),
		Blockchain: Blockchain{
			Blocks: make([]Block, 0),
			mu:     sync.Mutex{},
		},
	}

	return node, nil
}

func generateRandomID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func (n *Node) StartNode() {
	listener, err := net.Listen("tcp", n.Addresses[0])
	if err != nil {
		fmt.Println("Error starting listener.", err)
		os.Exit(1)
	}

	defer listener.Close()

	fmt.Printf("Node %s listening on %s\n", n.ID, n.Addresses[0])

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		go n.handleConnection(conn)
	}
}

func (n *Node) handleConnection(conn net.Conn) {
	defer conn.Close()

	decoder := gob.NewDecoder(conn)
	var message Message
	err := decoder.Decode(&message)
	if err != nil {
		fmt.Println("Error decoding message:", err)
		return
	}

	if message.Block.Index > len(n.Blockchain.Blocks) {

		n.Blockchain.mu.Lock()
		n.Blockchain.Blocks = append(n.Blockchain.Blocks, message.Block)
		n.Blockchain.mu.Unlock()
		fmt.Printf("Received block from %s = Index: %d\n", message.From, message.Block.Index)
	}
}

func (n *Node) SendMessage(to *Node, content string) {
	n.Blockchain.mu.Lock()
	defer n.Blockchain.mu.Unlock()

	message := Message{
		From:    n.ID,
		Content: content,
		Block:   n.Blockchain.Blocks[len(n.Blockchain.Blocks)-1],
	}

	conn, err := net.Dial("tcp", to.Addresses[0])
	if err != nil {
		fmt.Println("Error connecting to node:", err)
		return
	}
	defer conn.Close()

	encoder := gob.NewEncoder(conn)
	err = encoder.Encode(&message)
	if err != nil {
		fmt.Println("Error encoding message:", err)
		return
	}

	fmt.Printf("Sent message to %s: %s\n", to.ID, content)
}

func (n *Node) RunAll() {
	n.StartNode()
	// Add more function calls if needed
}

func CreateNodes() {
	node1, err := NewNode()
	if err != nil {
		fmt.Println("Error creating node:", err)
		os.Exit(1)
	}

	node1.Addresses = append(node1.Addresses, "localhost:8080")

	node2, err := NewNode()
	if err != nil {
		fmt.Println("Error creating node:", err)
		os.Exit(1)
	}

	node2.Addresses = append(node2.Addresses, "localhost:8081")

	go node1.RunAll()
	go node2.RunAll()

	node1.SendMessage(node2, "Hello from Node1")

	node2.SendMessage(node1, "Hello from Node2")

	// Print blockchain details for both nodes
	fmt.Printf("\nBlockchain Details for Node %s:\n", node1.ID)
	for _, block := range node1.Blockchain.Blocks {
		fmt.Printf("Index: %d\n", block.Index)
		fmt.Printf("Timestamp: %v\n", block.Timestamp)
		fmt.Printf("Hash: %x\n", block.Hash)
		fmt.Printf("Previous Hash: %x\n", block.PreviousHash)
		fmt.Println("----------------------------")
	}

	fmt.Printf("\nBlockchain Details for Node %s:\n", node2.ID)
	for _, block := range node2.Blockchain.Blocks {
		fmt.Printf("Index: %d\n", block.Index)
		fmt.Printf("Timestamp: %v\n", block.Timestamp)
		fmt.Printf("Hash: %x\n", block.Hash)
		fmt.Printf("Previous Hash: %x\n", block.PreviousHash)
		fmt.Println("----------------------------")
	}

	// Keep the main thread alive
	select {}
}
