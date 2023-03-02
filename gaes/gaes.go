package gaes

type Mode string

const (
	ECBMode Mode = "ECB"
	CBCMode Mode = "CBC"
	CTRMode Mode = "CTR"
	OFBMode Mode = "OFB"
	CFBMode Mode = "CFB"
)

type Padding string

const (
	Pkcs5Padding Padding = "pkcs5padding"
	Pkcs7Padding Padding = "pkcs7padding"
	ZeroPadding  Padding = "zeropadding"
	ISO10126     Padding = "iso10126"
	ANSIX923     Padding = "ansix923"
	NoPadding    Padding = "nopadding"
)

func Encrypt(mode Mode, padding Padding, key []byte, iv []byte, data []byte) ([]byte, error) {
	// padding
	paddingData := dataPadding(padding, data)

	return nil, nil
}

func Decrypt(mode Mode, padding Padding, key []byte, iv []byte, data []byte) ([]byte, error) {

	return nil, nil
}

func pkcs5Padding(data []byte) []byte {

}

func pkcs7Padding(data []byte) []byte {

}

func zeroPadding(data []byte) []byte {

}

func iso10126(data []byte) []byte {

}

func ansix923(data []byte) []byte {

}

func dataPadding(padding Padding, data []byte) []byte {
	switch padding {
	case Pkcs5Padding:
		return pkcs5Padding(data)
	case Pkcs7Padding:
		return pkcs7Padding(data)
	case ZeroPadding:
		return zeroPadding(data)
	case ISO10126:
		return iso10126(data)
	case ANSIX923:
		return ansix923(data)
	case NoPadding:
		return data
	default:
		panic("unknown padding")
	}
}

func unPadding(padding Padding, data []byte) []byte {
	switch padding {
	case Pkcs5Padding:
		return pkcs5Padding(data)
	case Pkcs7Padding:
		return pkcs7Padding(data)
	case ZeroPadding:
		return zeroPadding(data)
	case ISO10126:
		return iso10126(data)
	case ANSIX923:
		return ansix923(data)
	case NoPadding:
		return data
	default:
		panic("unknown padding")
	}
}
