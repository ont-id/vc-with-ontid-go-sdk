# VC With ONT ID Go SDK
* [VC With ONT ID Go SDK](#vc-with-ontid-go-sdk)
    * [1. Overview](#1-overview)
    * [2. VC API](#2-vc-api)
        * [2.1 Get PublicKey From DID](#21-get-publickey-from-did)
        * [2.2 Register VC On Chain](#22-register-vc-on-chain)
        * [2.3 Revoke VC On Chain](#23-revoke-vc-on-chain)
        * [2.4 Get VC Status On Chain](#24-get-vc-status-on-chain)

## 1. Overview
This is a comprehensive Verifiable Credential with ONT ID library written in the Go Language.


## 2. VC API

### 2.1 Get PublicKey From DID

```
/ @title GetPublicKeyFromDid
// @description	Get the specific public key from a DID
// @param     did	string	    "a DID"
// @param     keyId	string	    "the verification method identifier"
// @return    a public key

func (this *VcStatusSdk) GetPublicKeyFromDID(did, keyId string) (*vc.PublicKey, error) {

type PublicKey struct {
	Id           string `json:"id"`
	Type         string `json:"type"`
	PublicKeyHex string `json:"publicKeyHex"`
}

```

### 2.2 Register VC On Chain


```
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

func (this *VcStatusSdk) RegisterVCOnChain(contractAddress string, vcId, issuerId, holderId string, gasPrice, gasLimit uint64, signer, payer *ontsdk.Account) (string, error)


```

### 2.3 Revoke VC On Chain

```
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

func (this *VcStatusSdk) RevokeVCOnChain(contractAddress string, vcId, issuerId, holderId string, gasPrice, gasLimit uint64, signer, payer *ontsdk.Account) (string, error)

```

### 2.4 Get VC Status On Chain


```
// @title CommitVCStatusToChain
// @description Revoke the VC on the blockchain network described in the VC's credentialStatus field and make the on-chain status revoked.
//@param contractAddress string "the ont chain did contract addr"
// @param     credential	*VerifiableCredential	    "a verifiable credential to be checked"
// @return    the VC's on-chain status

func (this *VcStatusSdk) GetVCStatusOnChain(contractAddress string, credential *vc.VerifiableCredential) (int64, error)


```
