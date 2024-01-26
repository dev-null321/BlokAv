package main


import(
  "fmt"
  "os"
)


func main (){
  
    fmt.Println("[1] Connect to BlockAV (Initialize connection to the BlockAV network)")
    fmt.Println("[2] Run Quick Scan (Perform a quick scan of your system for known threats)")
    fmt.Println("[3] Run Behavioral Scan (Perform a behavioral analysis scan for potential threats)")
    fmt.Println("[4] Upload File To BlockAV (Contribute to the BlockAV network by uploading a file for analysis)")
    

    var choice int
    fmt.Scanln(&choice)

    if choice == 2{
      fmt.Println("Running quick scan")
      AVScan()
    } 

    if choice == 3{
      fmt.Println("Running behavioral scan")
      AVScan()
      TmpfsSandbox()
   }
          



























}
