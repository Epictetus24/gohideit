# gohideit

Simple Dropper Automation tool just enough to automate using some common go payloads from the following repo:

https://github.com/Ne0nd0g/go-shellcode

I have also included the "BasicObf" payload which has the bare basics in the file to be compatible with the tool, you can modify it as you like.

## Install
To use gohide it you will need to install go, as we'll need the go compiler to compile our droppers.

For linux:

```sh
sudo apt update && sudo apt install golang
git clone https://github.com/Epictetus24/gohideit
```

## Usage
Once downloaded it's fairly simple, you can either compile the binary and run it that way, or use it with "go run". However, please note that the tool needs to be run in a folder with the cmd/ payload directory as this is where it looks for the available payloads. Any other go payloads you put in there will show as options to use, but please note they must match the template (BasicObf.go) to actually work.

```sh
go run main.go -i <exe/binfile> -key <AES Key String> -xor <XOR Key> -o <output executable>
```
[![asciicast](https://asciinema.org/a/nyFglEvadib7FNVGwTzK62cb4.png)](https://asciinema.org/a/nyFglEvadib7FNVGwTzK62cb4)

## Notes
Currently this will only generate 64 bit exe's, which is all I plan to use this for. If you need 32bit, you can tweak the code (generate.go), but I don't support 32-bit myself so please don't come to me if your payload of choice does not work.

There are plans to support more, but I suggest you write your own bespoke payloads for most scenarios - this is just for quick wins against simple AV.

## Planned Features:

* ~~Support for generating shellcode from binaries using donut.~~
* Support for using [garble](https://github.com/burrowers/garble) against your binary when you are done.
* GO Dll's for DLL based actions such as dll reflection and rundll32.
