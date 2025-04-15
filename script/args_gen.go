package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/RSSU-Shellcode/GRT-Develop/argument"
)

func main() {
	args := []*argument.Arg{
		{ID: 1, Data: []byte{0xFF}}, // invalid PE image config
	}
	stub, err := argument.Encode(args...)
	checkError(err)

	fmt.Println("============x86============")
	fmt.Println(dumpBytesHex(stub))
	fmt.Println("===========================")

	fmt.Println()

	args = []*argument.Arg{
		{ID: 1, Data: []byte{0xFE}}, // invalid PE image config
	}
	stub, err = argument.Encode(args...)
	checkError(err)

	fmt.Println("============x64============")
	fmt.Println(dumpBytesHex(stub))
	fmt.Println("===========================")
}

func dumpBytesHex(b []byte) string {
	n := len(b)
	builder := bytes.Buffer{}
	builder.Grow(len("0FFh, ")*n - len(", "))
	buf := make([]byte, 2)
	var counter = 0
	for i := 0; i < n; i++ {
		if counter == 0 {
			builder.WriteString("  db ")
		}
		hex.Encode(buf, b[i:i+1])
		builder.WriteString("0")
		builder.Write(bytes.ToUpper(buf))
		builder.WriteString("h")
		if i == n-1 {
			builder.WriteString("\r\n")
			break
		}
		counter++
		if counter != 4 {
			builder.WriteString(", ")
			continue
		}
		counter = 0
		builder.WriteString("\r\n")
	}
	return builder.String()
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
