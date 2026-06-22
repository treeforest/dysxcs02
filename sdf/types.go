package sdf

// SysConf 对应 C 结构体 SysConf。
type SysConf struct {
	Timeout   uint32
	WorkType  uint32
	MaxCipher uint32
	IP        [MaxCipherHosts][16]byte
	Port      [MaxCipherHosts]uint32
}

// DeviceInfo 对应 C 结构体 DEVICEINFO。
type DeviceInfo struct {
	IssuerName      [40]byte
	DeviceName      [16]byte
	DeviceSerial    [16]byte
	DeviceVersion   uint32
	StandardVersion uint32
	AsymAlgAbility  [2]uint32
	SymAlgAbility   uint32
	HashAlgAbility  uint32
	BufferSize      uint32
}

// RSAPublicKey 对应 C 结构体 RSArefPublicKey。
type RSAPublicKey struct {
	Bits uint32
	M    []byte
	E    []byte
}

// RSAPrivateKey 对应 C 结构体 RSArefPrivateKey。
type RSAPrivateKey struct {
	Bits  uint32
	M     []byte
	E     []byte
	D     []byte
	Prime [2][]byte
	PExp  [2][]byte
	Coef  []byte
}

// RSAPublicKeyLite 对应 C 结构体 RSArefPublicKeyLite。
type RSAPublicKeyLite struct {
	Bits uint32
	M    []byte
	E    []byte
}

// RSAPrivateKeyLite 对应 C 结构体 RSArefPrivateKeyLite。
type RSAPrivateKeyLite struct {
	Bits  uint32
	M     []byte
	E     []byte
	D     []byte
	Prime [2][]byte
	PExp  [2][]byte
	Coef  []byte
}

// RSAPublicKeyOLD 对应 C 结构体 RSArefPublicKey_OLD。
type RSAPublicKeyOLD struct {
	Bits uint32
	M    []byte
	E    []byte
}

// RSAPrivateKeyOLD 对应 C 结构体 RSArefPrivateKey_OLD。
type RSAPrivateKeyOLD struct {
	Bits  uint32
	M     []byte
	E     []byte
	D     []byte
	Prime [2][]byte
	PExp  [2][]byte
	Coef  []byte
}

// ECCPublicKey 对应 C 结构体 ECCrefPublicKey。
type ECCPublicKey struct {
	Bits uint32
	X    []byte
	Y    []byte
}

// ECCPrivateKey 对应 C 结构体 ECCrefPrivateKey。
type ECCPrivateKey struct {
	Bits uint32
	K    []byte
}

// ECCCipher 对应 C 结构体 ECCCipher（可变长 C 字段）。
type ECCCipher struct {
	X []byte
	Y []byte
	M [32]byte
	L uint32
	C []byte
}

// ECCSignature 对应 C 结构体 ECCSignature。
type ECCSignature struct {
	R []byte
	S []byte
}

// EnvelopedKeyBlob 对应 C 结构体 ENVELOPEDKEYBLOB。
type EnvelopedKeyBlob struct {
	AsymmAlgID    uint32
	SymmAlgID     uint32
	ECCCipherBlob ECCCipher
	PubKey        ECCPublicKey
	EncryptedKey  [64]byte
}

// ECCPublicKeyECDSA 对应 C 结构体 ECCrefPublicKey_ECDSA。
type ECCPublicKeyECDSA struct {
	Bits uint32
	X    []byte
	Y    []byte
}

// ECCPrivateKeyECDSA 对应 C 结构体 ECCrefPrivateKey_ECDSA。
type ECCPrivateKeyECDSA struct {
	Bits uint32
	K    []byte
}

// ECCSignatureECDSA 对应 C 结构体 ECCSignature_ECDSA。
type ECCSignatureECDSA struct {
	R []byte
	S []byte
}

// ECCPublicKeyEDDSA 对应 C 结构体 ECCrefPublicKey_EDDSA。
type ECCPublicKeyEDDSA struct {
	Bits uint32
	Pub  []byte
}

// ECCPrivateKeyEDDSA 对应 C 结构体 ECCrefPrivateKey_EDDSA。
type ECCPrivateKeyEDDSA struct {
	Bits uint32
	Pri  []byte
}

// ECCSignatureEDDSA 对应 C 结构体 ECCSignature_EDDSA。
type ECCSignatureEDDSA struct {
	R []byte
	S []byte
}

// DSAPublicKey 对应 C 结构体 DSArefPublicKey。
type DSAPublicKey struct {
	Bits uint32
	Y    []byte
	P    []byte
	Q    []byte
	G    []byte
}

// DSAPrivateKey 对应 C 结构体 DSArefPrivateKey。
type DSAPrivateKey struct {
	Bits uint32
	X    []byte
	P    []byte
	Q    []byte
	G    []byte
}

// DSASignature 对应 C 结构体 DSASignature。
type DSASignature struct {
	R []byte
	S []byte
}

// SM9MasterPrivateKey 对应 C 结构体 SM9MasterPrivateKey。
type SM9MasterPrivateKey struct {
	Bits uint32
	S    []byte
}

// SM9SignMasterPublicKey 对应 C 结构体 SM9SignMasterPublicKey。
type SM9SignMasterPublicKey struct {
	Bits uint32
	XA   []byte
	XB   []byte
	YA   []byte
	YB   []byte
}

// SM9EncMasterPublicKey 对应 C 结构体 SM9EncMasterPublicKey。
type SM9EncMasterPublicKey struct {
	Bits uint32
	X    []byte
	Y    []byte
}

// SM9UserSignPrivateKey 对应 C 结构体 SM9UserSignPrivateKey。
type SM9UserSignPrivateKey struct {
	Bits uint32
	X    []byte
	Y    []byte
}

// SM9UserEncPrivateKey 对应 C 结构体 SM9UserEncPrivateKey。
type SM9UserEncPrivateKey struct {
	Bits uint32
	XA   []byte
	XB   []byte
	YA   []byte
	YB   []byte
}

// SM9Cipher 对应 C 结构体 SM9Cipher（可变长 C 字段）。
type SM9Cipher struct {
	EnType uint32
	X      []byte
	Y      []byte
	H      []byte
	L      uint32
	C      []byte
}

// SM9Signature 对应 C 结构体 SM9Signature。
type SM9Signature struct {
	H []byte
	X []byte
	Y []byte
}

// SM9KeyPackage 对应 C 结构体 SM9KeyPackage。
type SM9KeyPackage struct {
	X []byte
	Y []byte
}

// SM9PairEncEnvelopedKey 对应 C 结构体 SM9PairEncEnvelopedKey。
type SM9PairEncEnvelopedKey struct {
	Version         uint32
	SymAlgID        uint32
	Bits            uint32
	EncryptedPriKey []byte
	EncMastPubKey   SM9EncMasterPublicKey
	UserIDLen       uint32
	UserID          []byte
	KeyLen          uint32
	KeyPackage      SM9KeyPackage
}

// SM9PairSignEnvelopedKey 对应 C 结构体 SM9PairSignEnvelopedKey。
type SM9PairSignEnvelopedKey struct {
	Version         uint32
	SymAlgID        uint32
	Bits            uint32
	EncryptedPriKey []byte
	SignMastPubKey  SM9SignMasterPublicKey
	UserIDLen       uint32
	UserID          []byte
	KeyLen          uint32
	KeyPackage      SM9KeyPackage
}

// HashCtx 对应 SDFE_Hash* 使用的 512 字节上下文。
type HashCtx [512]byte
