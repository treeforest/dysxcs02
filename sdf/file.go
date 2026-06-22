package sdf

/*
#cgo CFLAGS: -I${SRCDIR}/../include -DMAXCIPHER=16
#cgo LDFLAGS: -L${SRCDIR}/../lib -lsdf -Wl,-rpath,${SRCDIR}/../lib -Wl,--allow-shlib-undefined -Wl,--unresolved-symbols=ignore-all

#include <stdlib.h>
#include <string.h>
#include "libsdf.h"
*/
import "C"



import "unsafe"

// CreateFile 创建设备文件（SDF_CreateFile）。
func (s *Session) CreateFile(name string, fileSize uint32) error {
	cName, nameLen := fileNameToC(name)
	rv := RV(C.SDF_CreateFile(cHandle(s.h), cName, nameLen, C.uint(fileSize)))
	return Err(rv)
}

// ReadFile 读取设备文件（SDF_ReadFile）。
func (s *Session) ReadFile(name string, offset uint32, length uint32) ([]byte, error) {
	cName, nameLen := fileNameToC(name)
	readLen := C.uint(length)
	buf := make([]byte, length)
	rv := RV(C.SDF_ReadFile(cHandle(s.h), cName, nameLen, C.uint(offset), &readLen, (*C.uchar)(unsafe.Pointer(&buf[0]))))
	if err := Err(rv); err != nil {
		return nil, err
	}
	return buf[:readLen], nil
}

// WriteFile 写入设备文件（SDF_WriteFile）。
func (s *Session) WriteFile(name string, offset uint32, data []byte) error {
	cName, nameLen := fileNameToC(name)
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_WriteFile(cHandle(s.h), cName, nameLen, C.uint(offset), C.uint(len(data)), puc))
	return Err(rv)
}

// DeleteFile 删除设备文件（SDF_DeleteFile）。
func (s *Session) DeleteFile(name string) error {
	cName, nameLen := fileNameToC(name)
	rv := RV(C.SDF_DeleteFile(cHandle(s.h), cName, nameLen))
	return Err(rv)
}

func fileNameToC(name string) (*C.uchar, C.uint) {
	b := []byte(name)
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.uchar)(unsafe.Pointer(&b[0])), C.uint(len(b))
}
