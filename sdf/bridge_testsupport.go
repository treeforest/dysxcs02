//go:build integration

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

func eccPublicKeyAlloc(g *ECCPublicKey) (*C.ECCrefPublicKey, func()) {
	c := eccPublicKeyToC(g)
	return c, func() { C.free(unsafe.Pointer(c)) }
}

func rsaPublicKeyAlloc(g *RSAPublicKey) (*C.RSArefPublicKey, func()) {
	c := rsaPublicKeyToC(g)
	return c, func() { C.free(unsafe.Pointer(c)) }
}

func deviceInfoFromTestFields(deviceName string, deviceVersion uint32) *DeviceInfo {
	c := (*C.DEVICEINFO)(C.calloc(1, C.size_t(unsafe.Sizeof(C.DEVICEINFO{}))))
	defer C.free(unsafe.Pointer(c))
	name := append([]byte(deviceName), 0)
	C.memcpy(unsafe.Pointer(&c.DeviceName[0]), unsafe.Pointer(&name[0]), C.size_t(len(name)))
	c.DeviceVersion = C.uint(deviceVersion)
	return deviceInfoFromC(c)
}
