package exe

import (
	"log"
	"os"

	"github.com/Binject/go-donut/donut"
)

func ShellcodeFromExe(srcFile string) {

	donutArch := donut.X64

	config := new(donut.DonutConfig)
	config.Arch = donutArch
	config.Entropy = uint32(2)
	config.OEP = uint64(0)

	config.InstType = donut.DONUT_INSTANCE_PIC

	config.Entropy = uint32(3)
	config.Bypass = 3
	config.Compress = uint32(1)
	config.Format = uint32(1)
	config.Verbose = true

	config.ExitOpt = uint32(1)
	payload, err := donut.ShellcodeFromFile(srcFile, config)
	if err == nil {
		f, err := os.Create("loader.bin")
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		if _, err = payload.WriteTo(f); err != nil {
			log.Fatal(err)
		}
	}

	if err != nil {
		log.Println(err)
	} else {
		log.Println("Donutting Done!")
	}
}
