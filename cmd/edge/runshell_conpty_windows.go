//go:build windows

package main

import (
	"fmt"
	"io"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

func startInteractiveShellConPTY(channel io.ReadWriter, cols, rows uint32) {
	// Create pipes
	var inRead, inWrite, outRead, outWrite windows.Handle
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{}))}
	sa.InheritHandle = 1

	if err := windows.CreatePipe(&inRead, &inWrite, sa, 0); err != nil {
		fmt.Fprintf(channel, "CreatePipe(in): %v\r\n", err)
		return
	}
	if err := windows.CreatePipe(&outRead, &outWrite, sa, 0); err != nil {
		fmt.Fprintf(channel, "CreatePipe(out): %v\r\n", err)
		return
	}

	// Create pseudo console
	var console windows.Handle
	if cols == 0 {
		cols = 120
	}
	if rows == 0 {
		rows = 30
	}
	size := windows.Coord{X: int16(cols), Y: int16(rows)}
	if err := windows.CreatePseudoConsole(size, inRead, outWrite, 0, &console); err != nil {
		fmt.Fprintf(channel, "CreatePseudoConsole: %v\r\n", err)
		return
	}

	// Set up startup info with pseudo console attribute
	attrList, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		fmt.Fprintf(channel, "NewProcThreadAttributeList: %v\r\n", err)
		return
	}
	defer attrList.Delete()

	if err := attrList.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, unsafe.Pointer(console), unsafe.Sizeof(console)); err != nil {
		fmt.Fprintf(channel, "Update attr: %v\r\n", err)
		return
	}

	si := &windows.StartupInfoEx{}
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.ProcThreadAttributeList = attrList.List()

	// Launch process
	cmdLine := "cmd.exe"
	cmdLinePtr, _ := windows.UTF16PtrFromString(cmdLine)

	pi := &windows.ProcessInformation{}
	err = windows.CreateProcess(
		nil,
		cmdLinePtr,
		nil,
		nil,
		false,
		windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT,
		nil,
		nil,
		&si.StartupInfo,
		pi,
	)
	if err != nil {
		fmt.Fprintf(channel, "CreateProcess: %v\r\n", err)
		return
	}

	// Close handles we don't need
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(inRead)
	windows.CloseHandle(outWrite)

	// Goroutine: read from output pipe → SSH channel
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			var n uint32
			err := windows.ReadFile(outRead, buf, &n, nil)
			if err != nil || n == 0 {
				break
			}
			channel.Write(buf[:n])
		}
	}()

	// Goroutine: read from SSH channel → input pipe
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := channel.Read(buf)
			if err != nil || n == 0 {
				break
			}
			// Write to input pipe
			var written uint32
			windows.WriteFile(inWrite, buf[:n], &written, nil)
		}
	}()

	// Wait for process to exit
	windows.WaitForSingleObject(pi.Process, windows.INFINITE)
	windows.CloseHandle(pi.Process)

	// Cleanup
	windows.CloseHandle(inWrite)
	windows.CloseHandle(outRead)
	windows.ClosePseudoConsole(console)

	wg.Wait()
}
