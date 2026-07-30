//go:build darwin || linux

package objfile

import (
	"os"
	"syscall"
)

// mmapFile maps path read-only. The returned close releases the
// mapping; the file descriptor is closed before returning.
func mmapFile(path string) (data []byte, close func() error, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if info.Size() == 0 {
		return nil, func() error { return nil }, nil
	}
	data, err = syscall.Mmap(int(f.Fd()), 0, int(info.Size()),
		syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, nil, err
	}
	return data, func() error { return syscall.Munmap(data) }, nil
}
