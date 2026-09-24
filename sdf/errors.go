package sdf

import "fmt"

// RV 表示 SDF 返回码（SGD_RV）。
type RV uint32

// SDF 返回码常量（与规范 SDR_* 符号对应）。
const (
	RVOK RV = 0x00000000

	rvBase = 0x01000000

	RVUnknown           RV = rvBase + 0x00000001
	RVGeneralError      RV = rvBase + 0x00000001
	RVNotSupport        RV = rvBase + 0x00000002
	RVCommFail          RV = rvBase + 0x00000003
	RVHardFail          RV = rvBase + 0x00000004
	RVOpenDevice        RV = rvBase + 0x00000005
	RVOpenSession       RV = rvBase + 0x00000006
	RVParDeny           RV = rvBase + 0x00000007
	RVKeyNotExist       RV = rvBase + 0x00000008
	RVAlgNotSupport     RV = rvBase + 0x00000009
	RVAlgModNotSupport  RV = rvBase + 0x0000000A
	RVPKOpErr           RV = rvBase + 0x0000000B
	RVSKOpErr           RV = rvBase + 0x0000000C
	RVSignErr           RV = rvBase + 0x0000000D
	RVVerifyErr         RV = rvBase + 0x0000000E
	RVSymOpErr          RV = rvBase + 0x0000000F
	RVStepErr           RV = rvBase + 0x00000010
	RVFileSizeErr       RV = rvBase + 0x00000011
	RVFileNoExist       RV = rvBase + 0x00000012
	RVFileOfsErr        RV = rvBase + 0x00000013
	RVKeyTypeErr        RV = rvBase + 0x00000014
	RVKeyErr            RV = rvBase + 0x00000015
	RVEncDataErr        RV = rvBase + 0x00000016
	RVRandErr           RV = rvBase + 0x00000017
	RVPrkrErr           RV = rvBase + 0x00000018
	RVMacErr            RV = rvBase + 0x00000019
	RVFileExists        RV = rvBase + 0x0000001A
	RVFileWErr          RV = rvBase + 0x0000001B
	RVNoBuffer          RV = rvBase + 0x0000001C
	RVInArgErr          RV = rvBase + 0x0000001D
	RVOutArgErr         RV = rvBase + 0x0000001F

	RVArgumentsBad = RVInArgErr

	rvDayou = 0x80000000

	RVBufferTooSmall       RV = rvDayou + 0x00000001
	RVObjectExist          RV = rvDayou + 0x00000002
	RVObjectNotExist       RV = rvDayou + 0x00000003
	RVMallocError          RV = rvDayou + 0x00000004
	RVEncodeError          RV = rvDayou + 0x0000FFFE
	RVDecodeError          RV = rvDayou + 0x0000FFFD
	RVInvalidInstruction   RV = rvDayou + 0x0000FFFC
	RVFunctionNotSupported RV = rvDayou + 0x0000FFFB
	RVWaitTimeout          RV = rvDayou + 0x0000FFFA
	RVIncompletePackage    RV = rvDayou + 0x0000FFF9
)

var rvNames = map[RV]string{
	RVOK:                 "SDR_OK",
	RVUnknown:            "SDR_UNKNOWERR",
	RVNotSupport:         "SDR_NOTSUPPORT",
	RVCommFail:             "SDR_COMMFAIL",
	RVHardFail:             "SDR_HARDFAIL",
	RVOpenDevice:           "SDR_OPENDEVICE",
	RVOpenSession:          "SDR_OPENSESSION",
	RVParDeny:              "SDR_PARDENY",
	RVKeyNotExist:          "SDR_KEYNOTEXIST",
	RVAlgNotSupport:        "SDR_ALGNOTSUPPORT",
	RVAlgModNotSupport:     "SDR_ALGMODNOTSUPPORT",
	RVPKOpErr:              "SDR_PKOPERR",
	RVSKOpErr:              "SDR_SKOPERR",
	RVSignErr:              "SDR_SIGNERR",
	RVVerifyErr:            "SDR_VERIFYERR",
	RVSymOpErr:             "SDR_SYMOPERR",
	RVStepErr:              "SDR_STEPERR",
	RVFileSizeErr:          "SDR_FILESIZEERR",
	RVFileNoExist:          "SDR_FILENOEXIST",
	RVFileOfsErr:           "SDR_FILEOFSERR",
	RVKeyTypeErr:           "SDR_KEYTYPEERR",
	RVKeyErr:               "SDR_KEYERR",
	RVEncDataErr:           "SDR_ENCDATAERR",
	RVRandErr:              "SDR_RANDERR",
	RVPrkrErr:              "SDR_PRKRERR",
	RVMacErr:               "SDR_MACERR",
	RVFileExists:           "SDR_FILEEXISTS",
	RVFileWErr:             "SDR_FILEWERR",
	RVNoBuffer:             "SDR_NOBUFFER",
	RVInArgErr:             "SDR_INARGERR",
	RVOutArgErr:            "SDR_OUTARGERR",
	RVBufferTooSmall:       "SDR_BUFFER_TOO_SMALL",
	RVObjectExist:          "SDR_OBJECT_EXIST",
	RVObjectNotExist:       "SDR_OBJECT_NOT_EXIST",
	RVMallocError:          "SDR_MALLOC_ERROR",
	RVEncodeError:          "SDR_ENCODE_ERROR",
	RVDecodeError:          "SDR_DECODE_ERROR",
	RVInvalidInstruction:   "SDR_INVALID_INSTRUCTION",
	RVFunctionNotSupported: "SDR_FUNCITON_NOT_SUPPORTED", //nolint:misspell // 厂商 SDK 原始符号名
	RVWaitTimeout:          "SDR_WAIT_TIMEOUT",
	RVIncompletePackage:    "SDR_INCOMPLETE_PACKAGE",
}

// Error 将返回码包装为 error。
type Error struct {
	Code RV
}

func (e *Error) Error() string {
	return fmt.Sprintf("sdf: %s (0x%08x)", e.Code.String(), uint32(e.Code))
}

// String 返回 SDR_* 符号名。
func (c RV) String() string {
	if name, ok := rvNames[c]; ok {
		return name
	}
	return fmt.Sprintf("SDR_UNKNOWN_0x%08x", uint32(c))
}

// Err 若 rv 非 RVOK 则返回 *Error，否则返回 nil。
func Err(rv RV) error {
	if rv == RVOK {
		return nil
	}
	return &Error{Code: rv}
}
