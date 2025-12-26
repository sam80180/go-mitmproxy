//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func setproctitle(newTitle string) error {
	// Structures required for PEB traversal
	type ProcessBasicInformation struct {
		Reserved1       uintptr
		PebBaseAddress  uintptr
		Reserved2       [2]uintptr
		UniqueProcessId uintptr
		Reserved3       uintptr
	} // end type

	type UnicodeString struct {
		Length        uint16
		MaximumLength uint16
		Buffer        uintptr
	} // end type

	ntdll := syscall.NewLazyDLL("ntdll.dll")
	procNtQueryInfo := ntdll.NewProc("NtQueryInformationProcess")
	hProcess := windows.CurrentProcess()

	// 1. Get PEB Address
	var pbi ProcessBasicInformation
	var returnLen uint32
	status, _, _ := procNtQueryInfo.Call(
		uintptr(hProcess),
		0, // ProcessBasicInformation class
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if status != 0 {
		return fmt.Errorf("NtQueryInformationProcess failed with status: %x", status)
	} // end if

	// 2. Read PEB to find ProcessParameters pointer
	// Offset for ProcessParameters in PEB on x64 is 0x20
	var processParametersPtr uintptr
	if err := windows.ReadProcessMemory(hProcess, pbi.PebBaseAddress+0x20, (*byte)(unsafe.Pointer(&processParametersPtr)), 8, nil); err != nil {
		return err
	} // end if

	// 3. Read CommandLine UNICODE_STRING
	// Offset for CommandLine in ProcessParameters on x64 is 0x70
	var cmdLine UnicodeString
	cmdLineOffset := processParametersPtr + 0x70
	if err := windows.ReadProcessMemory(hProcess, cmdLineOffset, (*byte)(unsafe.Pointer(&cmdLine)), unsafe.Sizeof(cmdLine), nil); err != nil {
		return err
	} // end if

	// 4. Prepare the fake title (UTF16)
	newTitlePtr, err := windows.UTF16PtrFromString(newTitle)
	if err != nil {
		return err
	} // end if
	newLen := uint16(len(windows.StringToUTF16(newTitle)) * 2)

	// Ensure we don't cause a buffer overflow in the existing allocation
	if newLen > cmdLine.MaximumLength {
		return fmt.Errorf("new title is too long for existing buffer")
	} // end if

	// 5. Overwrite the buffer and update length
	if err := windows.WriteProcessMemory(hProcess, cmdLine.Buffer, (*byte)(unsafe.Pointer(newTitlePtr)), uintptr(newLen), nil); err != nil {
		return err
	} // end if

	// Update the Length field in the UNICODE_STRING structure
	return windows.WriteProcessMemory(hProcess, cmdLineOffset, (*byte)(unsafe.Pointer(&newLen)), 2, nil)
} // end setproctitle()
