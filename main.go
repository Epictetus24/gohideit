package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/Epictetus24/gohideit/config"
	"github.com/Epictetus24/gohideit/exe"
	"github.com/Epictetus24/gohideit/gen"
	"github.com/fatih/color"
)

func init() {
	if _, err := os.Stat("./goenv.txt"); errors.Is(err, os.ErrNotExist) {
		config.GoGetEnv()
	}
}

func main() {

	key := flag.String("key", "", " AES Encryption key")
	xor := flag.String("xor", "", "XOR Encryption key")
	input := flag.String("i", "", "Input file path of binary file")
	output := flag.String("o", "", "Output file path")
	//goobf := flag.Bool("garble", false, "Use garble against final binary")

	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	if *key == "" {
		color.Red("[!]A key must be provided with the -key parameter to encrypt the input file")
		os.Exit(1)
	}

	if *xor == "" {
		color.Red("[!]A XOR key must be provided with the -xor parameter to encrypt the input file strings")
		os.Exit(1)
	}

	if *input == "" {
		color.Red("[!]An input raw binary - *.bin file must be provided with -i.")
		os.Exit(1)
	}

	if *output == "" {
		color.Red("[!]An output file must be provided with the -output parameter such as  -output=evil.exe ")
		os.Exit(1)
	}

	// Check to make sure an output file was provided
	if *output == "" {
		color.Red("[!]The -o output argument is required")
		os.Exit(1)
	}

	// Check to make sure the output directory exists
	dir, outFile := filepath.Split(*output)
	color.Yellow(fmt.Sprintf("[-]Output directory: %s", dir))
	color.Yellow(fmt.Sprintf("[-]Output file name: %s", outFile))

	if strings.Contains(*input, ".exe") {
		exe.ShellcodeFromExe(*input)
		shellcode, errShellcode := ioutil.ReadFile("loader.bin")

		if errShellcode != nil {
			color.Red(fmt.Sprintf("[!]%s", errShellcode.Error()))
			os.Exit(1)
		}
		color.Yellow("Exe detected as an input file, attempting to generate shellcode with go-donut.")

		gen.Generate(*output, *xor, *key, shellcode)

	} else {
		shellcode, errShellcode := ioutil.ReadFile(*input)

		if errShellcode != nil {
			color.Red(fmt.Sprintf("[!]%s", errShellcode.Error()))
			os.Exit(1)
		}
		gen.Generate(*output, *xor, *key, shellcode)
	}

}
