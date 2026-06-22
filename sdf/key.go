package sdf

/*
#cgo CFLAGS: -I${SRCDIR}/../include -DMAXCIPHER=16
#cgo LDFLAGS: -L${SRCDIR}/../lib -lsdf -Wl,-rpath,${SRCDIR}/../lib -Wl,--allow-shlib-undefined -Wl,--unresolved-symbols=ignore-all

#include <stdlib.h>
#include <string.h>
#include "libsdf.h"
*/
import "C"



// Close 销毁对称密钥句柄（SDF_DestroyKey）。
func (k *KeyHandle) Close() error {
	if k == nil || k.h == nil || k.session == nil {
		return nil
	}
	rv := RV(C.SDF_DestroyKey(cHandle(k.session.h), cHandle(k.h)))
	k.h = nil
	return Err(rv)
}

// Close 释放 ECC 私钥句柄（SDF_DestroyKey_Handle_ECC）。
func (e *ECCKeyHandle) Close() error {
	if e == nil || e.h == nil || e.session == nil {
		return nil
	}
	rv := RV(C.SDF_DestroyKey_Handle_ECC(cHandle(e.session.h), cHandle(e.h)))
	e.h = nil
	return Err(rv)
}

// Close 释放协商句柄（当前无独立 C API，仅清空引用）。
func (a *AgreementHandle) Close() error {
	a.h = nil
	return nil
}
