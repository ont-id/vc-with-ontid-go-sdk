package vc_with_ontid_go_sdk

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	vc "github.com/ont-id/verifiable-credential-go-sdk"
	"github.com/ontio/ontology-crypto/keypair"
	ontsdk "github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/common"
)

type VcStatusSdk struct {
	ontSdk *ontsdk.OntologySdk
}

func NewVcStatusSdk(rpcAddr string) *VcStatusSdk {
	ontSdk := ontsdk.NewOntologySdk()
	ontSdk.NewRpcClient().SetAddress(rpcAddr)
	return &VcStatusSdk{ontSdk: ontSdk}
}

// @title GetPublicKeyFromDid
// @description	Get the specific public key from a DID
// @param     did	string	    "a DID"
// @param     keyId	string	    "the verification method identifier"
// @return    a public key
func (this *VcStatusSdk) GetPublicKeyFromDID(did, keyId string) (*vc.PublicKey, error) {
	publicKeyList, err := this.getPublicKeyListByOntID(did)
	if err != nil {
		return nil, err
	}
	for _, v := range publicKeyList {
		if v.Id == keyId {
			return v, nil
		}
	}
	return nil, fmt.Errorf("GetPublicKeyId, record not found")
}

// @title RegisterVCOnChain
// @description Register the VC on the blockchain network described in the VC's credentialStatus field and make the on-chain status active. This function can be only called by the issuer.
//@param contractAddress string "the ont chain did contract addr"
// @param     vcId	 	 string	    "the identifier of the VC
// @param     issuerId	 string	    "the identifier of the issuer"
// @param     holderId	 string	    "the identifier of the holder"
// @param     gasPrice	 uint64	    "gas price"
// @param     gasLimit	 uint64	    "gas limit"
// @param     signer	 crypto.PrivateKey	"the private key of the issuer"
// @param     payer	 crypto.PrivateKey	"the private ket of the payer"
// @return the transaction hash
func (this *VcStatusSdk) RegisterVCOnChain(contractAddress string, vcId, issuerId, holderId string, gasPrice, gasLimit uint64, signer, payer *ontsdk.Account) (string, error) {
	pkList, err := this.getPublicKeyListByOntID(issuerId)
	if err != nil {
		return "", err
	}
	contractAddr, err := common.AddressFromHexString(contractAddress)
	if err != nil {
		return "", err
	}
	index := uint32(0)
	publicKeyHex := hex.EncodeToString(keypair.SerializePublicKey(signer.PublicKey))
	for i, v := range pkList {
		if v.PublicKeyHex == publicKeyHex {
			index = uint32(i + 1)
			break
		}
	}
	if index == 0 {
		return "", fmt.Errorf("GetPublicKeyId, record not found")
	}
	params := []interface{}{"Commit", []interface{}{vcId, issuerId, index, holderId}}
	txHash, err := this.ontSdk.NeoVM.InvokeNeoVMContract(gasPrice, gasLimit, payer, signer, contractAddr, params)
	if err != nil {
		return "", fmt.Errorf("CommitCredential, this.ontSdk.NeoVM.InvokeNeoVMContract error: %s", err)
	}
	return txHash.ToHexString(), nil

}

// @title RevokeVCOnChain
// @description Revoke the VC on the blockchain network described in the VC's credentialStatus field and make the on-chain status revoked. This function can be only called by the issuer or the holder.
// @description Register the VC on the blockchain network described in the VC's credentialStatus field and make the on-chain status active. This function can be only called by the issuer.
//@param contractAddress string "the ont chain did contract addr"
// @param     vcId	     string	    "the identifier of the VC
// @param     issuerId	 string	    "the identifier of the issuer"
// @param     holderId	 string	    "the identifier of the holder"
// @param     gasPrice	 uint64	    "gas price"
// @param     gasLimit	 uint64	    "gas limit"
// @param     signer	 crypto.PrivateKey	"the private key of the issuer"
// @param     payer	 crypto.PrivateKey	"the private ket of the payer"
// @return the transaction hash
func (this *VcStatusSdk) RevokeVCOnChain(contractAddress string, vcId, issuerId, holderId string, gasPrice, gasLimit uint64, signer, payer *ontsdk.Account) (string, error) {
	contractAddr, err := common.AddressFromHexString(contractAddress)
	if err != nil {
		return "", err
	}
	index, _, err := this.getPublicKeyId(holderId, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return "", fmt.Errorf("RevokeCredentialByHolder, this.GetPublicKeyId error: %s", err)
	}
	params := []interface{}{"Revoke", []interface{}{vcId, issuerId, index}}
	txHash, err := this.ontSdk.NeoVM.InvokeNeoVMContract(gasPrice, gasLimit, payer, signer, contractAddr, params)
	if err != nil {
		return "", fmt.Errorf("revokeCredential, this.ontSdk.NeoVM.InvokeNeoVMContract error: %s", err)
	}
	return txHash.ToHexString(), nil
}

// @title CommitVCStatusToChain
// @description Revoke the VC on the blockchain network described in the VC's credentialStatus field and make the on-chain status revoked.
//@param contractAddress string "the ont chain did contract addr"
// @param     credential	*VerifiableCredential	    "a verifiable credential to be checked"
// @return    the VC's on-chain status
func (this *VcStatusSdk) GetVCStatusOnChain(contractAddress string, credential *vc.VerifiableCredential) (int64, error) {
	params := []interface{}{"GetStatus", []interface{}{credential.Id}}
	contractAddr, err := common.AddressFromHexString(contractAddress)
	if err != nil {
		return -1, err
	}
	preExecResult, err := this.ontSdk.NeoVM.PreExecInvokeNeoVMContract(contractAddr, params)
	if err != nil {
		return -1, fmt.Errorf("getCredentialStatus, this.ontSdk.NeoVM.PreExecInvokeNeoVMContract error: %s", err)
	}
	r, err := preExecResult.Result.ToInteger()
	if err != nil {
		return -1, fmt.Errorf("getCredentialStatus, preExecResult.Result.ToInteger error: %s", err)
	}
	return r.Int64(), nil
}

func (this *VcStatusSdk) getPublicKeyListByOntID(ontId string) ([]*vc.PublicKey, error) {
	publicKeys, err := this.ontSdk.Native.OntId.GetPublicKeysJson(ontId)
	if err != nil {
		return nil, fmt.Errorf("GetPublicKeyList, this.ontSdk.Native.OntId.GetPublicKeysJson error: %s", err)
	}
	var publicKeyList []*vc.PublicKey
	err = json.Unmarshal(publicKeys, &publicKeyList)
	if err != nil {
		return nil, fmt.Errorf("GetPublicKeyList, json.Unmarshal publicKeyList error: %s", err)
	}
	return publicKeyList, nil
}

func (this *VcStatusSdk) getPublicKeyId(ontId string, publicKeyHex string) (uint32, *vc.PublicKey, error) {
	publicKeyList, err := this.getPublicKeyListByOntID(ontId)
	if err != nil {
		return 0, nil, fmt.Errorf("GetPublicKeyId, this.GetPublicKeyList error: %s", err)
	}
	for i, v := range publicKeyList {
		if v.PublicKeyHex == publicKeyHex {
			return uint32(i + 1), v, nil
		}
	}
	return 0, nil, fmt.Errorf("GetPublicKeyId, record not found")
}
