package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Epictetus24/gohideit/gen"
	"github.com/fatih/color"
)

func govars() {
	out, err := exec.Command("go", "env").Output()
	if err != nil {
		log.Fatal(err)
	}

	output := string(out)

	file, err := os.Create("config/goenv.txt")
	if err != nil {
		fmt.Println(err)
	} else {
		file.WriteString(output)
		fmt.Println("Go ENV run, and variables saved in config/goenv.txt")
	}

}

func init() {
	govars()
}

func main() {

	key := flag.String("key", "", " AES Encryption key")
	xor := flag.String("xor", "", "XOR Encryption key")
	input := flag.String("i", "", "Input file path of binary file")
	output := flag.String("o", "", "Output file path")
	//goobf := flag.Bool("gobf", false, "Use go-obfuscate against final binary")

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
		color.Red("[!]An input raw binary - *.bin file must be provided with -input.")
		os.Exit(1)
	}

	if *output == "" {
		color.Red("[!]An output file must be provided with the -output parameter such as  -output=evil.exe ")
		os.Exit(1)
	}

	if strings.Contains(*input, ".exe") {

	}

	shellcode, errShellcode := ioutil.ReadFile(*input)

	if errShellcode != nil {
		color.Red(fmt.Sprintf("[!]%s", errShellcode.Error()))
		os.Exit(1)
	}

	// Check to make sure an output file was provided
	if *output == "" {
		color.Red("[!]The -o output argument is required")
		os.Exit(1)
	}
	dir, outFile := filepath.Split(*output)

	// Check to make sure the output directory exists
	dir, outFile = filepath.Split(*output)
	color.Yellow(fmt.Sprintf("[-]Output directory: %s", dir))
	color.Yellow(fmt.Sprintf("[-]Output file name: %s", outFile))

	//if exe do donut stuff then the rest
	// something like donut.converttoshellcode(binaryfile)
	//else if bin do aes enc and the rest

	//promptui stuff for choosing payload

	gen.Generate(1, *output, *xor, *key, shellcode)

	/*

		generate payload




		If goobf == true {

			check if goobfuscate is installed, if not recommend user download it:


			do gobf stuff to binary

			save output file seperately

			exit
		}

		else
		just save the generated binary

	*/

}
