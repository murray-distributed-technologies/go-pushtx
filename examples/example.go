package main

import (
	"fmt"

	"github.com/libsv/go-bk/wif"
	"github.com/libsv/go-bt/v2"
	"github.com/libsv/go-bt/v2/bscript"
	"github.com/murray-distributed-technologies/go-pushtx/internal/woc"
	pushtx "github.com/murray-distributed-technologies/go-pushtx/transaction"
)

func main() {
	childPrivKey, _ := wif.DecodeWIF("<Key 1>")
	parentPrivKey, _ := wif.DecodeWIF("<Key 2>")
	pubKey := childPrivKey.PrivKey.PubKey()
	address, _ := bscript.NewAddressFromPublicKey(pubKey, true)
	var sats uint64
	var vOut uint32

	txId := "<TX_ID"
	vOut = 0
	amount := uint64(3000)

	o, _ := woc.GetTransactionOutput(txId, int(vOut))

	sats = uint64(o.Value * 100000000)
	scriptPubKey, err := bscript.NewFromHexString(o.ScriptPubKey.Hex)
	if err != nil {
		fmt.Println(err)
	}

	input := &bt.Input{
		PreviousTxSatoshis: sats,
		PreviousTxScript:   scriptPubKey,
		PreviousTxOutIndex: vOut,
	}

	rawTx, err := pushtx.NewOpPushTransaction(input, txId, address.AddressString, address.AddressString, parentPrivKey.PrivKey, amount)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(rawTx)

}
