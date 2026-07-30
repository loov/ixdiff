//go:build !darwin && !linux

package objfile

import "os"

// mmapFile reads path into memory on platforms without a wired-up
// mmap; the interface matches the real mapping.
func mmapFile(path string) (data []byte, close func() error, err error) {
	data, err = os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return data, func() error { return nil }, nil
}
