package main

import (
	"bytes"
	"debug/pe"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/RSSU-Shellcode/GRT-Develop/option"
	"github.com/RSSU-Shellcode/GRT-MXLoader/loader"
)

var (
	tplDir  string
	typ     string
	mode    string
	arch    int
	payload string

	options   loader.Options
	compress  bool
	comWindow int
	httpOpts  loader.HTTPOptions

	outPath string
)

func init() {
	flag.StringVar(&tplDir, "tpl", "template", "set shellcode templates directory")
	flag.StringVar(&typ, "type", "", "select the template type")
	flag.StringVar(&mode, "mode", "", "select the payload load mode")
	flag.IntVar(&arch, "arch", 0, "set shellcode template architecture")
	flag.StringVar(&payload, "payload", "", "set the input payload file path")
	flag.StringVar(&options.ImageName, "im", "", "set the image name about command line for .NET")
	flag.StringVar(&options.CommandLine, "cmd", "", "set the command line for .NET exe")
	flag.BoolVar(&options.WaitMain, "wait", false, "wait for .NET exe to exit")
	flag.BoolVar(&options.AllowSkipDLL, "skip-dll", false, "allow skip DLL if failed to load for .NET")
	flag.BoolVar(&compress, "compress", true, "compress image when use embed mode")
	flag.IntVar(&comWindow, "window", 4096, "set the window size when use compression")
	flag.StringVar(&outPath, "o", "output.bin", "set output shellcode file path")
	option.Flag(&options.Runtime)
	flag.Parse()
}

func main() {
	if payload == "" {
		flag.Usage()
		return
	}

	fmt.Println("load PE Loader templates")
	ldrX64, err := os.ReadFile(filepath.Join(tplDir, "PELoader_x64.bin")) // #nosec
	checkError(err)
	ldrX86, err := os.ReadFile(filepath.Join(tplDir, "PELoader_x86.bin")) // #nosec
	checkError(err)

	// create image config
	var image loader.Image
	switch mode {
	case "embed":
		fmt.Println("use embed image mode")
		fmt.Println("parse PE image file")
		peData, err := os.ReadFile(payload) // #nosec
		checkError(err)
		peFile, err := pe.NewFile(bytes.NewReader(peData))
		checkError(err)
		switch peFile.OptionalHeader.(type) {
		case *pe.OptionalHeader64:
			arch = 64
			fmt.Println("image architecture: x64")
		case *pe.OptionalHeader32:
			arch = 32
			fmt.Println("image architecture: x86")
		default:
			fmt.Println("unknown optional header type")
			return
		}
		if compress {
			fmt.Println("enable PE image compression")
			s := (len(peData) / (2 * 1024 * 1024)) + 1
			fmt.Printf("please wait for about %d seconds for compress\n", s)
			image = loader.NewEmbedCompress(peData, comWindow)
		} else {
			image = loader.NewEmbed(peData)
		}
	case "file":
		fmt.Println("use local file mode")
		image = loader.NewFile(payload)
	case "http":
		fmt.Println("use http mode")
		image = loader.NewHTTP(payload, &httpOpts)
	default:
		fmt.Println("unknown load mode")
		return
	}

	// select shellcode template
	var template []byte
	switch arch {
	case 32:
		template = ldrX86
		fmt.Println("select template for x86")
	case 64:
		template = ldrX64
		fmt.Println("select template for x64")
	default:
		fmt.Println("unknown template architecture")
		return
	}

	fmt.Println("generate GRT-PELoader from template")
	inst, err := loader.CreateInstance(template, arch, image, &options)
	checkError(err)

	outPath, err = filepath.Abs(outPath)
	checkError(err)
	fmt.Println("save instance to:", outPath)
	err = os.WriteFile(outPath, inst, 0600)
	checkError(err)

	fmt.Println("generate shellcode successfully")
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
