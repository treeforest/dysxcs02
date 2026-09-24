package sdf

/*
#cgo CFLAGS: -I${SRCDIR}/../include -DMAXCIPHER=16
#cgo LDFLAGS: -L${SRCDIR}/../lib -lsdf -Wl,-rpath,${SRCDIR}/../lib -Wl,--allow-shlib-undefined -Wl,--unresolved-symbols=ignore-all

#include <stdlib.h>
#include <string.h>
#include "libsdf.h"
*/
import "C"



import (
	"unsafe"
)

const defaultOutBufSize = 4096

// bytesOut 为可变长度 C 输出缓冲区提供两阶段分配：先探测长度，再取回数据。
func bytesOut(initial uint32, fn func(buf *C.uchar, length *C.uint) C.int) ([]byte, error) {
	size := initial
	if size == 0 {
		size = defaultOutBufSize
	}
	for {
		buf := (*C.uchar)(C.malloc(C.size_t(size)))
		length := C.uint(size)
		rv := RV(fn(buf, &length))
		if rv == RVBufferTooSmall {
			C.free(unsafe.Pointer(buf))
			size = uint32(length)
			if size == 0 {
				size = defaultOutBufSize * 2
			}
			continue
		}
		if err := Err(rv); err != nil {
			C.free(unsafe.Pointer(buf))
			return nil, err
		}
		out := C.GoBytes(unsafe.Pointer(buf), C.int(length))
		C.free(unsafe.Pointer(buf))
		return out, nil
	}
}

// bytesOutFixed 在调用方已知缓冲区大小时使用。
func bytesOutFixed(buf []byte, fn func(buf *C.uchar, length *C.uint) C.int) ([]byte, error) {
	if len(buf) == 0 {
		buf = make([]byte, defaultOutBufSize)
	}
	for {
		cBuf := (*C.uchar)(C.malloc(C.size_t(len(buf))))
		length := C.uint(len(buf))
		rv := RV(fn(cBuf, &length))
		if rv == RVBufferTooSmall {
			C.free(unsafe.Pointer(cBuf))
			buf = make([]byte, int(length))
			continue
		}
		if err := Err(rv); err != nil {
			C.free(unsafe.Pointer(cBuf))
			return nil, err
		}
		out := C.GoBytes(unsafe.Pointer(cBuf), C.int(length))
		C.free(unsafe.Pointer(cBuf))
		return out, nil
	}
}

func goBytesToC(b []byte) (*C.uchar, C.uint) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.uchar)(C.CBytes(b)), C.uint(len(b))
}

func freeCBytes(p *C.uchar) {
	if p != nil {
		C.free(unsafe.Pointer(p))
	}
}

func cString(s string) *C.char {
	return C.CString(s)
}

func freeCString(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

func copyToCBytes(dst *C.uchar, src []byte) {
	if len(src) == 0 || dst == nil {
		return
	}
	C.memcpy(unsafe.Pointer(dst), unsafe.Pointer(&src[0]), C.size_t(len(src)))
}

func copyFixed(dst unsafe.Pointer, dstLen int, src []byte) {
	if dst == nil || len(src) == 0 {
		return
	}
	n := min(len(src), dstLen)
	C.memcpy(dst, unsafe.Pointer(&src[0]), C.size_t(n))
}

// copyFixedRightAligned 将 src 右对齐写入固定长度 C 缓冲区（密码机大端坐标/密钥格式）。
func copyFixedRightAligned(dst unsafe.Pointer, dstLen int, src []byte) {
	if dst == nil || dstLen <= 0 {
		return
	}
	C.memset(dst, 0, C.size_t(dstLen))
	if len(src) == 0 {
		return
	}
	n := len(src)
	if n > dstLen {
		src = src[len(src)-dstLen:]
		n = dstLen
	}
	offset := dstLen - n
	C.memcpy(unsafe.Add(dst, offset), unsafe.Pointer(&src[0]), C.size_t(n))
}

func effectiveLen(bits uint32, maxLen int) int {
	return min(int((bits+7)/8), maxLen)
}

func trimZeros(b []byte) []byte {
	i := len(b)
	for i > 0 && b[i-1] == 0 {
		i--
	}
	return b[:i]
}

func trimLeadingZeros(b []byte) []byte {
	i := 0
	for i < len(b) && b[i] == 0 {
		i++
	}
	return b[i:]
}
