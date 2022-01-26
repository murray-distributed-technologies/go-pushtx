package script

import (
	"encoding/hex"
	"fmt"

	"github.com/libsv/go-bt/v2/bscript"
	"github.com/libsv/go-bt/v2/sighash"
)

func AppendP2PKH(s *bscript.Script, address string) (*bscript.Script, error) {
	a, err := bscript.NewAddressFromString(address)
	if err != nil {
		return nil, err
	}

	var publicKeyHashBytes []byte
	if publicKeyHashBytes, err = hex.DecodeString(a.PublicKeyHash); err != nil {
		return nil, err
	}

	if err = s.AppendOpcodes(bscript.OpDUP, bscript.OpHASH160); err != nil {
		return nil, err
	}
	if err = s.AppendPushData(publicKeyHashBytes); err != nil {
		return nil, err
	}
	if err = s.AppendOpcodes(bscript.OpEQUALVERIFY, bscript.OpCHECKSIG); err != nil {
		return nil, err
	}
	return s, nil
}

// TODO: Not good checking because we haven't standardized Script Template
// Assumes OpPUSHTX is first thing on the stack
func IsOpPushTx(s *bscript.Script) bool {
	//var err error
	//b := []byte(*s)
	//rValueBytes, err := hex.DecodeString("3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817980220")
	//if err != nil {
	//	return false
	//}
	//data65, err := hex.DecodeString("41")
	//if err != nil {
	//	return false
	//}
	//pubKeyHashBytes, err := hex.DecodeString("02b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0")
	//if err != nil {
	//	return false
	//}
	return true
	//return b[1] == bscript.OpPICK &&
	//	b[2] == bscript.OpHASH256 &&
	//	b[3] == bscript.OpSPLIT &&
	//	b[4] == bscript.OpSWAP &&
	//	b[5] == bscript.OpBIN2NUM &&
	//	b[6] == bscript.Op1ADD &&
	//	b[7] == bscript.OpSWAP &&
	//	b[8] == bscript.OpCAT //&&
	//b[9] == rValueBytes &&
	//b[10] == bscript.OpSWAP &&
	//b[11] == bscript.OpCAT &&
	//b[12] == data65 &&
	//b[13] == bscript.OpCAT &&
	//b[14] == pubKeyHashBytes &&
	//(b[15] == bscript.OpCHECKSIG || b[15] == bscript.OpCHECKSIGVERIFY)

}

// AppendPushTx assumes preimage in the unlocking script
// Leaves a copy of the preimage on the stack

func AppendPushTx(s *bscript.Script) (*bscript.Script, error) {
	var err error
	// Add number of items back in the stack preimage is
	_ = s.AppendOpcodes(bscript.Op0)
	// Copy preimage to top of the stack
	_ = s.AppendOpcodes(bscript.OpPICK)
	// Double SHA256 hash preimage
	_ = s.AppendOpcodes(bscript.OpHASH256)
	// Split first byte of preimage hash, move to top of the stack, convert to num, and add 1
	err = s.AppendOpcodes(bscript.Op1)
	if err != nil {
		return nil, err
	}
	s.AppendOpcodes(bscript.OpSPLIT)
	s.AppendOpcodes(bscript.OpSWAP)
	s.AppendOpcodes(bscript.OpBIN2NUM)
	s.AppendOpcodes(bscript.Op1ADD)

	// Concatenate new first byte with preimage hash
	s.AppendOpcodes(bscript.OpSWAP)
	s.AppendOpcodes(bscript.OpCAT)

	// Push r derived from Optimized OP_PUSH_TX private key
	if err = s.AppendPushDataHexString("3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817980220"); err != nil {
		return nil, err
	}

	s.AppendOpcodes(bscript.OpSWAP)
	s.AppendOpcodes(bscript.OpCAT)
	// Push OP_DATA_65 to stack
	opData65Bytes, err := hex.DecodeString("41")
	if err != nil {
		return nil, err
	}
	if err = s.AppendPushData(opData65Bytes); err != nil {
		fmt.Println(err)
	}

	s.AppendOpcodes(bscript.OpCAT)

	// Push Public Key derived from Optimized OP_PUSH_TX private key
	pubKeyHashBytes, err := hex.DecodeString("02b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0")
	if err != nil {
		return nil, err
	}
	if err = s.AppendPushData(pubKeyHashBytes); err != nil {
		return nil, err
	}

	// CHECKSIGVERY is performed against signature to validate we have pushed the current transaction

	s.AppendOpcodes(bscript.OpCHECKSIGVERIFY)

	// drop preimage from the stack
	s.AppendOpcodes(bscript.OpDROP)

	return s, nil
}

// NewP2PKHUnlockingScript creates an unlocking script <sig> <pubkey> <preimage>

func NewPushTxUnlockingScript(pubKey, preimage, sig []byte, sigHashFlag sighash.Flag) (*bscript.Script, error) {
	sigBuf := []byte{}
	sigBuf = append(sigBuf, sig...)
	sigBuf = append(sigBuf, uint8(sigHashFlag))

	scriptBuf := [][]byte{sigBuf, pubKey}
	s := &bscript.Script{}
	err := s.AppendPushDataArray(scriptBuf)
	if err != nil {
		return nil, err
	}
	if err = s.AppendPushData(preimage); err != nil {
		return nil, err
	}

	return s, nil

}

func AppendGetLockingScriptFromPreimage(s *bscript.Script) (*bscript.Script, error) {
	//Assume Preimage is on top of the stack
	var err error

	// scriptCode begins at byte position 104
	// push 104 to stack (hex 0x68)
	if err = s.AppendPushDataHexString("68"); err != nil {
		return nil, err
	}

	s.AppendOpcodes(bscript.OpBIN2NUM)
	// split preimage at position 104
	s.AppendOpcodes(bscript.OpSPLIT)

	// duplicate to check script length
	//s.AppendOpCode(bscript.OpDUP)
	// script length is first byte of scriptCode
	// split script length and push it to top of stack

	s.AppendOpcodes(bscript.Op1)
	s.AppendOpcodes(bscript.OpSPLIT)
	s.AppendOpcodes(bscript.OpSWAP)
	s.AppendOpcodes(bscript.OpDUP)
	s.AppendOpcodes(bscript.OpDUP)
	s.AppendOpcodes(bscript.OpDUP)

	//check for varInt size
	if err = s.AppendPushDataHexString("ff"); err != nil {
		return nil, err
	}
	// if size is 5-8 bytes
	s.AppendOpcodes(bscript.OpNUMEQUAL)
	s.AppendOpcodes(bscript.OpIF)
	s.AppendOpcodes(bscript.Op2DROP)
	s.AppendOpcodes(bscript.OpDROP)
	s.AppendOpcodes(bscript.Op8)
	s.AppendOpcodes(bscript.OpSPLIT)
	s.AppendOpcodes(bscript.OpSWAP)

	//if size is fe (3-4 bytes)
	s.AppendOpcodes(bscript.OpELSE)
	if err = s.AppendPushDataHexString("fe"); err != nil {
		return nil, err
	}
	s.AppendOpcodes(bscript.OpNUMEQUAL)
	s.AppendOpcodes(bscript.OpIF)
	s.AppendOpcodes(bscript.Op2DROP)
	s.AppendOpcodes(bscript.Op4)
	s.AppendOpcodes(bscript.OpSPLIT)
	s.AppendOpcodes(bscript.OpSWAP)

	//if size is fd
	s.AppendOpcodes(bscript.OpELSE)
	if err = s.AppendPushDataHexString("fd"); err != nil {
		return nil, err
	}
	s.AppendOpcodes(bscript.OpNUMEQUAL)
	s.AppendOpcodes(bscript.OpIF)
	// split next two bytes for varInt
	s.AppendOpcodes(bscript.OpDROP)
	s.AppendOpcodes(bscript.Op2)
	s.AppendOpcodes(bscript.OpSPLIT)
	s.AppendOpcodes(bscript.OpSWAP)

	// else size is one byte
	s.AppendOpcodes(bscript.OpELSE)
	if err = s.AppendPushDataHexString("00"); err != nil {
		return nil, err
	}
	s.AppendOpcodes(bscript.OpCAT)
	s.AppendOpcodes(bscript.OpENDIF)
	s.AppendOpcodes(bscript.OpENDIF)
	s.AppendOpcodes(bscript.OpENDIF)

	s.AppendOpcodes(bscript.OpBIN2NUM)
	s.AppendOpcodes(bscript.OpSPLIT)

	// drop the rest of preimage off the stack
	s.AppendOpcodes(bscript.OpROT)
	s.AppendOpcodes(bscript.Op2DROP)

	// leaves the locking script on the stack

	return s, nil
}

// AppendSplitPushTxFromLockingScript
// Will split out the optimized push tx template from locking script, assuming it is the beginning of the script

func SplitPushTxFromLockingScript(s *bscript.Script) *bscript.Script {
	// assuming locking script is on the top of the stack
	// hex of pushtx = '0079aa517f7c818b7c7e263044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802207c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad'

	// SHA1 Hash = '4116009c9023cba646499e37b66874c7c1b1db1e'

	// PushTx script is 89 bytes
	//Split Locking script at 89 bytes (0x59)
	s.AppendPushDataHexString("59")
	s.AppendOpcodes(bscript.OpSWAP)

	return s
}
