package preimage

import (
	"reflect"
	"testing"
)

func TestParseHex(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		name             string
		preimageHex      string
		expectedError    bool
		expectedPreimage *Preimage
	}{
		{
			"valid preimage",
			"010000009a2fa936542fa3c61222edfe04cd69a4f5e152bc0248f6a48c8408e242610e8e3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e7066504445b546bce8be4cd4625399b780d7cc99bace957e3b4e72928ad1b9d71993fc5800000000c20079aa517f7c818b7c7e263044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802207c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad7514cb030491157b26a570b6ee91e5b068d99c3b72f6046d657461a72231346e64483972374e327072396d71793666536f635955483263534a707644394a71044e554c4c7176a9142989611fd22fb65e8d6bb2c2b4e3a2b10dc604dd88ad6d876a0774657374696e67d007000000000000ffffffff09488de72898e69b4be145d7f7e53bdc74069db4ba04a6be563e05e91c17c4770000000041000000",
			false,
			&Preimage{
				NVersion:     byteArray{1, 0, 0, 0},
				HashPrevouts: byteArray{154, 47, 169, 54, 84, 47, 163, 198, 18, 34, 237, 254, 4, 205, 105, 164, 245, 225, 82, 188, 2, 72, 246, 164, 140, 132, 8, 226, 66, 97, 14, 142},
				HashSequence: byteArray{0x3b, 0xb1, 0x30, 0x29, 0xce, 0x7b, 0x1f, 0x55, 0x9e, 0xf5, 0xe7, 0x47, 0xfc, 0xac, 0x43, 0x9f, 0x14, 0x55, 0xa2, 0xec, 0x7c, 0x5f, 0x9, 0xb7, 0x22, 0x90, 0x79, 0x5e, 0x70, 0x66, 0x50, 0x44},
				Outpoint:     byteArray{0x45, 0xb5, 0x46, 0xbc, 0xe8, 0xbe, 0x4c, 0xd4, 0x62, 0x53, 0x99, 0xb7, 0x80, 0xd7, 0xcc, 0x99, 0xba, 0xce, 0x95, 0x7e, 0x3b, 0x4e, 0x72, 0x92, 0x8a, 0xd1, 0xb9, 0xd7, 0x19, 0x93, 0xfc, 0x58, 0x0, 0x0, 0x0, 0x0},
				ScriptCode:   byteArray{0xc2, 0x0, 0x79, 0xaa, 0x51, 0x7f, 0x7c, 0x81, 0x8b, 0x7c, 0x7e, 0x26, 0x30, 0x44, 0x2, 0x20, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0xb, 0x7, 0x2, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98, 0x2, 0x20, 0x7c, 0x7e, 0x1, 0x41, 0x7e, 0x21, 0x2, 0xb4, 0x5, 0xd7, 0xf0, 0x32, 0x2a, 0x89, 0xd0, 0xf9, 0xf3, 0xa9, 0x8e, 0x6f, 0x93, 0x8f, 0xdc, 0x1c, 0x96, 0x9a, 0x8d, 0x13, 0x82, 0xa2, 0xbf, 0x66, 0xa7, 0x1a, 0xe7, 0x4a, 0x1e, 0x83, 0xb0, 0xad, 0x75, 0x14, 0xcb, 0x3, 0x4, 0x91, 0x15, 0x7b, 0x26, 0xa5, 0x70, 0xb6, 0xee, 0x91, 0xe5, 0xb0, 0x68, 0xd9, 0x9c, 0x3b, 0x72, 0xf6, 0x4, 0x6d, 0x65, 0x74, 0x61, 0xa7, 0x22, 0x31, 0x34, 0x6e, 0x64, 0x48, 0x39, 0x72, 0x37, 0x4e, 0x32, 0x70, 0x72, 0x39, 0x6d, 0x71, 0x79, 0x36, 0x66, 0x53, 0x6f, 0x63, 0x59, 0x55, 0x48, 0x32, 0x63, 0x53, 0x4a, 0x70, 0x76, 0x44, 0x39, 0x4a, 0x71, 0x4, 0x4e, 0x55, 0x4c, 0x4c, 0x71, 0x76, 0xa9, 0x14, 0x29, 0x89, 0x61, 0x1f, 0xd2, 0x2f, 0xb6, 0x5e, 0x8d, 0x6b, 0xb2, 0xc2, 0xb4, 0xe3, 0xa2, 0xb1, 0xd, 0xc6, 0x4, 0xdd, 0x88, 0xad, 0x6d, 0x87, 0x6a, 0x7, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67},
				Value:        byteArray{0xd0, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
				NSequence:    byteArray{0xff, 0xff, 0xff, 0xff},
				HashOutputs:  byteArray{0x9, 0x48, 0x8d, 0xe7, 0x28, 0x98, 0xe6, 0x9b, 0x4b, 0xe1, 0x45, 0xd7, 0xf7, 0xe5, 0x3b, 0xdc, 0x74, 0x6, 0x9d, 0xb4, 0xba, 0x4, 0xa6, 0xbe, 0x56, 0x3e, 0x5, 0xe9, 0x1c, 0x17, 0xc4, 0x77},
				NLocktime:    byteArray{0x0, 0x0, 0x0, 0x0},
				Sighash:      byteArray{0x41, 0x0, 0x0, 0x0},
			},
		},
		{
			"invalid preimage",
			"0100010001",
			true,
			nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, err := ParseHex(test.preimageHex)
			if err != nil && !test.expectedError {
				t.Errorf("%s failed: [%s] input, error: %v", test.name, test.preimageHex, err)
			}
			if !reflect.DeepEqual(p, test.expectedPreimage) {
				t.Errorf("%s failed: [%s] input, expected: %#v", test.name, test.preimageHex, test.expectedPreimage)
			}
		})
	}
}
