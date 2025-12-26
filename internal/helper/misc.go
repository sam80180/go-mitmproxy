package helper

import "unsafe"

func PtrID[T any](p *T) uintptr {
	return uintptr(unsafe.Pointer(p))
} // end PtrID()
