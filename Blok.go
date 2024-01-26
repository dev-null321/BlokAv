//AvBlock demo
// default repuation is a number between 1-100

package main 

import(
  "fmt"
  "time"
  "os"
  "math/rand"
)



type Node struct{
  
  upTime              time.Time
  DetermineReputation int
  Resources           []byte
  Hashes              []byte
}


func main(){

  rand.Seed(time.Now().UnixNano())
  
  trustedNode := Node{
    upTime := time.Now()
  }
    CurrentTime := time.Now()
    fmt.Println("Up time is %v\n", CurrentTime.Sub(trustedNode.UpTime))


    trustedNode.DetermineReputation = rand.Intn(100)
    if DetermineReputation >= 51{
        fmt.Println("Trusted Node")
  }else if DetermineReputation < 51{
      fmt.Println("This account is not a Trusted Node")
}
