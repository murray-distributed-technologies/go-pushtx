package preimage

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/libsv/go-bk/crypto"
	"github.com/libsv/go-bt/v2"
)

type byteArray []byte

type Preimage struct {
	NVersion     byteArray // nVersion of the transaction (4-byte little endian)
	HashPrevouts byteArray // (32-byte hash)
	HashSequence byteArray // (32-byte hash)
	Outpoint     byteArray // (32-byte hash + 4-byte little endian)
	ScriptCode   byteArray // scriptCode of the input (serialized as scripts inside CTxOuts)
	Value        byteArray // value of output spent by this input (8-byte little endian)
	NSequence    byteArray // nSequence (4-byte _ endian)
	HashOutputs  byteArray // (32-byte hash)
	NLocktime    byteArray // nLocktime of the transaction (4-byte little endian)
	Sighash      byteArray // sighash type of the signature (4-byte little endian)
}

func ParseHex(preimage string) (*Preimage, error) {
	b, err := hex.DecodeString(preimage)
	if err != nil {
		return nil, err
	}
	p, err := ParseBytes(b)
	if err != nil {
		return nil, err
	}
	return p, nil

}

func ParseBytes(preimage []byte) (*Preimage, error) {
	length := len(preimage)
	if length < 104 {
		return nil, errors.New("preimage length is bad, expected at least 104 bytes")
	}

	// check scriptCode length to splice appropriately

	scriptLenVarInt, sizeOfVarInt := bt.NewVarIntFromBytes(preimage[104:])
	scriptCodeStart := sizeOfVarInt + 104
	scriptCodeEnd := scriptCodeStart + int(scriptLenVarInt)
	endSplice := preimage[scriptCodeEnd:]

	// parse preimage

	p := &Preimage{
		NVersion:     preimage[0:4],
		HashPrevouts: preimage[4:36],
		HashSequence: preimage[36:68],
		Outpoint:     preimage[68:104],
		ScriptCode:   preimage[104:scriptCodeEnd],
		Value:        endSplice[0:8],
		NSequence:    endSplice[8:12],
		HashOutputs:  endSplice[12:44],
		NLocktime:    endSplice[44:48],
		Sighash:      endSplice[48:],
	}

	// check parsing
	// TODO: use fixed length bytes instead of this

	if len(p.Sighash) != 4 {
		return nil, errors.New("incorrect sighash length. something went wrong parsing preimage")
	}

	return p, nil

}

// BuildPreimage returns byte array of Preimage from Preimage type
func (p *Preimage) BuildPreimage() []byte {
	var preimage []byte
	preimage = append(preimage, p.NVersion.ToBytes()...)
	preimage = append(preimage, p.HashPrevouts.ToBytes()...)
	preimage = append(preimage, p.HashSequence.ToBytes()...)
	preimage = append(preimage, p.Outpoint.ToBytes()...)
	preimage = append(preimage, p.ScriptCode.ToBytes()...)
	preimage = append(preimage, p.Value.ToBytes()...)
	preimage = append(preimage, p.NSequence.ToBytes()...)
	preimage = append(preimage, p.HashOutputs.ToBytes()...)
	preimage = append(preimage, p.NLocktime.ToBytes()...)
	preimage = append(preimage, p.Sighash.ToBytes()...)
	return preimage

}

// get hex string of locking script from preimage
func (p *Preimage) GetLockingScriptHex() string {
	scriptCode := p.ScriptCode
	//Strip first byte which gives length of script
	lockingScript := scriptCode[1:]
	return lockingScript.ToHex()
}

func (b *byteArray) ToHex() string {
	return hex.EncodeToString(b.ToBytes())
}

func (b *byteArray) ToBytes() []byte {
	return []byte(*b)
}

// This library uses Optimized OP_PUSH_TX which requires low s value in signature
// This check will check the s value when hashing preimage and return malleated transaction if low s
// Malleates nLocktime until the most significant byte of Hash(preimage) is lower than 7e
// Note: This means this library will fail for any transactions that have nSequence set under MAX_UINT
func CheckForLowS(preimage []byte) ([]byte, uint32, error) {
	n := uint32(0)
	// if low s then malleate nLocktime until we get low S
	for !IsLowS(preimage) {

		parsedPreimage, err := ParseBytes(preimage)
		if err != nil {
			return nil, 0, err
		}
		nLocktime := parsedPreimage.NLocktime

		parsedPreimage.NLocktime, n = MalleateNLocktime(nLocktime, n)
		preimage = parsedPreimage.BuildPreimage()
		if !IsLowS(preimage) {
			continue
		}
	}

	return preimage, n, nil
}

func IsLowS(preimage []byte) bool {
	hash := crypto.Sha256d(preimage)
	slice1 := hex.EncodeToString(hash[0:1])
	num, err := strconv.ParseUint(slice1, 16, 8)
	if err != nil {
		return false
	}
	s, err := strconv.ParseUint("7e", 16, 8)
	if err != nil {
		return false
	}
	if num < s {
		return true
	}
	return false
}

func MalleateNLocktime(nLocktime byteArray, b uint32) (byteArray, uint32) {
	b += 1
	binary.LittleEndian.PutUint32(nLocktime, b)
	return nLocktime, b
}
