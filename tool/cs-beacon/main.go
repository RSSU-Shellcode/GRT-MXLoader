package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/RSSU-Shellcode/GRT-MXLoader/loader"
)

var (
	input  string
	output string
)

func init() {
	flag.StringVar(&input, "i", "beacon.exe", "stageless beacon exe file path")
	flag.StringVar(&output, "o", "stage.dll", "path for save stage dll file")
	flag.Parse()
}

func main() {
	beacon, err := os.ReadFile(input) // #nosec
	checkError(err)
	dll, err := loader.ExtractBeaconStage(beacon)
	checkError(err)
	err = os.WriteFile(output, dll, 0600)
	checkError(err)
	fmt.Println("extract Cobalt-Strike beacon stage successfully")
}

func checkError(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
