// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// +build windows

package windows

import (
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
)

// Syscalls
//sys   _GetProcessMemoryInfo(handle syscall.Handle, psmemCounters *ProcessMemoryCountersEx, cb uint32) (err error) = psapi.GetProcessMemoryInfo
//sys   _GetProcessImageFileNameA(handle syscall.Handle, imageFileName *byte, nSize uint32) (len uint32, err error) = psapi.GetProcessImageFileNameA

var (
	sizeofProcessMemoryCountersEx = uint32(unsafe.Sizeof(ProcessMemoryCountersEx{}))
)

// ProcessMemoryCountersEx is an equivalent representation of
// PROCESS_MEMORY_COUNTERS_EX in the Windows API. It contains information about
// the memory usage of a process.
// https://docs.microsoft.com/en-au/windows/desktop/api/psapi/ns-psapi-_process_memory_counters_ex
type ProcessMemoryCountersEx struct {
	cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

// GetProcessMemoryInfo retrieves memory info for the given process handle.
// https://docs.microsoft.com/en-us/windows/desktop/api/psapi/nf-psapi-getprocessmemoryinfo
func GetProcessMemoryInfo(process syscall.Handle) (ProcessMemoryCountersEx, error) {
	var info ProcessMemoryCountersEx
	if err := _GetProcessMemoryInfo(process, &info, sizeofProcessMemoryCountersEx); err != nil {
		return ProcessMemoryCountersEx{}, errors.Wrap(err, "GetProcessMemoryInfo failed")
	}
	return info, nil
}

// GetProcessImageFileName retrieves the process main executable.
// The returned path is a device path, that is:
// "\Device\HardDisk0Volume1\Windows\notepad.exe"
// instead of
// "C:\Windows\notepad.exe"
// Use QueryDosDevice or equivalent to convert to a drive path.
func GetProcessImageFileName(handle syscall.Handle) (string, error) {
	for bufLen, limit := syscall.MAX_PATH, syscall.MAX_PATH*4; bufLen <= limit; bufLen *= 2 {
		buf := make([]byte, bufLen)
		nameLen, err := _GetProcessImageFileNameA(handle, &buf[0], uint32(len(buf)))
		if err == nil {
			buf = buf[:nameLen]
			return string(buf), nil
		}
		if err != syscall.ERROR_INSUFFICIENT_BUFFER {
			return "", err
		}
	}
	return "", syscall.ERROR_INSUFFICIENT_BUFFER
}
