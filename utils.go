package vc_with_ontid_go_sdk

import (
	"crypto"
	"encoding/hex"
	"github.com/ontio/ontology-crypto/keypair"

	vc "github.com/ont-id/verifiable-credential-go-sdk"
	ontsdk "github.com/ontio/ontology-go-sdk"
)

func GetPublicKey(acc *ontsdk.Account) (*vc.PublicKey, crypto.PrivateKey) {
	pub := &vc.PublicKey{
		Id:           "",
		Type:         "",
		PublicKeyHex: hex.EncodeToString(keypair.SerializePublicKey(acc.PublicKey)),
	}
	return pub, acc.PrivateKey
}
