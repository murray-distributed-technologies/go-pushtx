package pushtx

import (
	"bytes"
	"context"
	"errors"

	"github.com/libsv/go-bk/bec"
	"github.com/libsv/go-bk/crypto"
	"github.com/libsv/go-bt/v2"
	"github.com/libsv/go-bt/v2/bscript"
	"github.com/libsv/go-bt/v2/sighash"
	btunlocker "github.com/libsv/go-bt/v2/unlocker"
	pushtxpreimage "github.com/murray-distributed-technologies/go-pushtx/preimage"
	"github.com/murray-distributed-technologies/go-pushtx/script"
)

/*
General Format of an OpPush Transaction
---------------------------------------

Unlocking Script: <sig> <pubKey> <preimage>

Locking Script: <Optimized OP_PUSH_TX> <P2PKH>


*/

func NewOpPushTransaction(input *bt.Input, txId, address, changeAddress string, privateKey *bec.PrivateKey, satoshis uint64) (string, error) {
	var err error
	tx := bt.NewTx()

	err = tx.From(txId, input.PreviousTxOutIndex, input.PreviousTxScript.String(), input.PreviousTxSatoshis)
	if err != nil {
		return "", err
	}

	// add OP_PUSH_TX in output 0
	if tx, err = AddOpPushTransactionOutput(tx, address, satoshis); err != nil {
		return "", err
	}

	// Add change output
	// TODO: not supported since not p2pkh, hardcode in for now
	if input.PreviousTxScript.IsP2PKH() {
		fq := bt.NewFeeQuote()
		if err = tx.ChangeToAddress(changeAddress, fq); err != nil {
			return "", err
		}
	}
	if !input.PreviousTxScript.IsP2PKH() {
		lockingScript, err := bscript.NewP2PKHFromAddress(changeAddress)
		if err != nil {
			return "", err
		}
		amount := (input.PreviousTxSatoshis - satoshis - 500)
		changeOutput := bt.Output{
			// Guess at 500 sats for fees to be safe
			Satoshis:      amount,
			LockingScript: lockingScript,
		}
		tx.AddOutput(&changeOutput)
	}

	unlocker := Getter{PrivateKey: privateKey}

	// Sign Input
	if err = tx.FillAllInputs(context.Background(), &unlocker); err != nil {
		return "", err
	}

	return tx.String(), nil
}

func AddOpPushTransactionOutput(tx *bt.Tx, address string, satoshis uint64) (*bt.Tx, error) {
	var err error
	s := &bscript.Script{}
	if s, err = script.AppendPushTx(s); err != nil {
		return nil, err
	}
	if s, err = script.AppendP2PKH(s, address); err != nil {
		return nil, err
	}
	lockingScript := s
	output := bt.Output{
		Satoshis:      satoshis,
		LockingScript: lockingScript,
	}
	tx.AddOutput(&output)
	return tx, nil

}

type Getter struct {
	PrivateKey *bec.PrivateKey
}

func (g *Getter) Unlocker(ctx context.Context, lockingScript *bscript.Script) (bt.Unlocker, error) {

	// if locking script is p2pkh do not add preimage to unlocking script
	if lockingScript.IsP2PKH() {
		return &btunlocker.Simple{PrivateKey: g.PrivateKey}, nil
	}
	// if locking script is OP_PUSH_TX add preimage to end of unlocking script
	if script.IsOpPushTx(lockingScript) {
		return &UnlockPushTx{PrivateKey: g.PrivateKey}, nil
	}
	return nil, errors.New("locking script not P2PKH or PushTx")

}

type UnlockPushTx struct {
	PrivateKey *bec.PrivateKey
}

// TODO: Currently only supports input 0
// Implements the bt.Unlocker interface
func (u *UnlockPushTx) UnlockingScript(ctx context.Context, tx *bt.Tx, params bt.UnlockerParams) (*bscript.Script, error) {
	if params.SigHashFlags == 0 {
		params.SigHashFlags = sighash.AllForkID
	}
	preimage, err := tx.CalcInputPreimage(params.InputIdx, params.SigHashFlags)
	if err != nil {
		return nil, err
	}
	preimage, nLockTime, err := pushtxpreimage.CheckForLowS(preimage)
	if err != nil {
		return nil, err
	}
	tx.LockTime = nLockTime

	// defaultHex is used to fix a bug in the original client (see if statement in the CalcInputSignatureHash func)
	var defaultHex = []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var sh []byte
	sh = crypto.Sha256d(preimage)

	if bytes.Equal(defaultHex, preimage) {
		sh = preimage
	}

	sig, err := u.PrivateKey.Sign(sh)
	if err != nil {
		return nil, err
	}

	pubKey := u.PrivateKey.PubKey().SerialiseCompressed()
	signature := sig.Serialise()

	uscript, err := script.NewPushTxUnlockingScript(pubKey, preimage, signature, params.SigHashFlags)
	if err != nil {
		return nil, err
	}

	return uscript, nil

}
