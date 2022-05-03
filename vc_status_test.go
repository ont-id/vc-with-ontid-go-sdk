package vc_with_ontid_go_sdk

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	vc "github.com/ont-id/verifiable-credential-go-sdk"
	"github.com/ontio/ontology-crypto/keypair"
	ontsdk "github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology/common"
	"github.com/stretchr/testify/assert"
)

const (
	CredentialCode = "59c56b05322e302e306a00527ac42241476d7269314b786847736b6d6a733236366f4a347066626b79336e784e6351613668204f6e746f6c6f67792e52756e74696d652e426173653538546f416464726573736a51527ac41400000000000000000000000000000000000000036a52527ac4681953797374656d2e53746f726167652e476574436f6e746578746a53527ac46c0123c56b6a00527ac46a51527ac46a52527ac46a51c306436f6d6d69747d9c7c75645c006a52c3c0547d9e7c75640a00006c75666203006a52c300c36a53527ac46a52c351c36a54527ac46a52c352c36a55527ac46a52c353c36a56527ac46a56c36a55c36a54c36a53c3546a00c306a502000000006e6c75666203006a51c3065265766f6b657d9c7c75644f006a52c3c0537d9e7c75640a00006c75666203006a52c300c36a53527ac46a52c351c36a58527ac46a52c352c36a55527ac46a55c36a58c36a53c3536a00c3065504000000006e6c75666203006a51c30652656d6f76657d9c7c75644f006a52c3c0537d9e7c75640a00006c75666203006a52c300c36a53527ac46a52c351c36a56527ac46a52c352c36a55527ac46a55c36a56c36a53c3536a00c3065306000000006e6c75666203006a51c3094765745374617475737d9c7c756435006a52c3c0517d9e7c75640a00006c75666203006a52c300c36a53527ac46a53c3516a00c3060708000000006e6c75666203006a51c307557067726164657d9c7c756483006a52c3c0577d9e7c75640a00006c75666203006a52c300c36a59527ac46a52c351c36a5a527ac46a52c352c36a5b527ac46a52c353c36a5c527ac46a52c354c36a5d527ac46a52c355c36a5e527ac46a52c356c36a5f527ac46a5fc36a5ec36a5dc36a5cc36a5bc36a5ac36a59c3576a00c306af08000000006e6c75666203006c75665fc56b6a00527ac46a51527ac46a52527ac46a53527ac46a54527ac46a55527ac46203006a54c36a53c352c66b6a00527ac46a51527ac46c6a56527ac46a56c30f7665726966795369676e61747572656a00c352c30068164f6e746f6c6f67792e4e61746976652e496e766f6b656a57527ac46a57c301017d9e7c7564290021636f6d6d697465724964207665726966795369676e6174757265206572726f722ef06203006a55c358007b6b766b946c6c52727f086469643a6f6e743a7d9e7c75641f0017696c6c6567616c206f776e6572496420666f726d61742ef06203006a52c36a00c353c3681253797374656d2e53746f726167652e4765746a58527ac46a58c3c0007d9e7c756425001d436f6d6d69742c20636c61696d496420616c7265616479206578697374f06203006a52c3516a53c36a55c354c176c96a59527ac46a59c3681853797374656d2e52756e74696d652e53657269616c697a656a58527ac46a58c36a52c36a00c353c3681253797374656d2e53746f726167652e5075746a55c36a53c36a52c306436f6d6d697454c1681553797374656d2e52756e74696d652e4e6f74696679516c75665fc56b6a00527ac46a51527ac46a52527ac46a53527ac46a54527ac46203006a54c36a53c352c66b6a00527ac46a51527ac46c6a55527ac46a55c30f7665726966795369676e61747572656a00c352c30068164f6e746f6c6f67792e4e61746976652e496e766f6b656a56527ac46a56c301017d9e7c756424001c6f6e744964207665726966795369676e6174757265206572726f722ef06203006a52c36a00c353c3681253797374656d2e53746f726167652e4765746a57527ac46a57c3c0007d9c7c756424001c5265766f6b652c20636c61696d496420646f206e6f74206578697374f06203006a57c3681a53797374656d2e52756e74696d652e446573657269616c697a656a58527ac46a58c3c0547d9f7c756427001f5265766f6b652c20696c6c6567616c20666f726d6174206f6620636c61696df06203006a58c352c36a53c37d9e7c7576641000756a58c353c36a53c37d9e7c756432002a5265766f6b652c206f6e74496420646f206e6f7420686176652061636365737320746f207265766f6b65f0620300006a58c3517bc46a58c3681853797374656d2e52756e74696d652e53657269616c697a656a59527ac46a59c36a52c36a00c353c3681253797374656d2e53746f726167652e5075746a53c36a52c3065265766f6b6553c1681553797374656d2e52756e74696d652e4e6f74696679516c75665dc56b6a00527ac46a51527ac46a52527ac46a53527ac46a54527ac46203006a54c36a53c352c66b6a00527ac46a51527ac46c6a55527ac46a55c30f7665726966795369676e61747572656a00c352c30068164f6e746f6c6f67792e4e61746976652e496e766f6b656a56527ac46a56c301017d9e7c756426001e6f776e65724964207665726966795369676e6174757265206572726f722ef06203006a52c36a00c353c3681253797374656d2e53746f726167652e4765746a57527ac46a57c3c0007d9c7c756424001c52656d6f76652c20636c61696d496420646f206e6f74206578697374f06203006a57c3681a53797374656d2e52756e74696d652e446573657269616c697a656a58527ac46a58c3c0547d9f7c756427001f52656d6f76652c20696c6c6567616c20666f726d6174206f6620636c61696df06203006a58c353c36a53c37d9e7c756420001852656d6f76652c206f776e657249642069732077726f6e67f06203006a52c36a00c353c3681553797374656d2e53746f726167652e44656c6574656a53c36a52c30652656d6f766553c1681553797374656d2e52756e74696d652e4e6f74696679516c75665ac56b6a00527ac46a51527ac46a52527ac46203006a52c36a00c353c3681253797374656d2e53746f726167652e4765746a53527ac46a53c3c0007d9c7c75640a00526c75666203006a53c3681a53797374656d2e52756e74696d652e446573657269616c697a656a54527ac46a54c3c0547d9f7c75642a00224765745374617475732c20696c6c6567616c20666f726d6174206f6620636c61696df06203006a54c351c36c75665ec56b6a00527ac46a51527ac46a52527ac46a53527ac46a54527ac46a55527ac46a56527ac46a57527ac46a58527ac46203006a00c351c3681b53797374656d2e52756e74696d652e436865636b5769746e65737391641b0013436865636b5769746e657373206661696c6564f06203006a58c36a57c36a56c36a55c36a54c36a53c36a52c368194f6e746f6c6f67792e436f6e74726163742e4d6967726174656a59527ac46a59c3916416000e4d696772617465206661696c6564f0620300516c7566"
)

var (
	testVcStatusSdk  *VcStatusSdk
	testWallet       *ontsdk.Wallet
	testContractAddr common.Address
	testPasswd       = []byte("123456")
	testDefAcc       *ontsdk.Account
	testGasPrice     = uint64(2500)
	testGasLimit     = uint64(20000)
	testRpcUrl       = "http://127.0.0.1:20336"
)

func init() {
	var err error
	var wallet *ontsdk.Wallet
	testOntSdk := ontsdk.NewOntologySdk()
	if !FileExisted("./wallet.dat") {
		wallet, err = testOntSdk.CreateWallet("./wallet.dat")
		if err != nil {
			fmt.Println("[CreateWallet] error:", err)
			return
		}
	} else {
		wallet, err = ontsdk.OpenWallet("./wallet.dat")
		if err != nil {
			fmt.Println("[CreateWallet] error:", err)
			return
		}
	}
	_, err = wallet.NewDefaultSettingAccount([]byte("123456"))
	if err != nil {
		fmt.Printf("NewDefaultSettingAccount err:%s\n", err)
		return
	}
	err = wallet.Save()
	if err != nil {
		fmt.Printf("wallet save err:%s\n", err)
		return
	}
	testWallet, err = ontsdk.OpenWallet("./wallet.dat")
	if err != nil {
		fmt.Printf("account.Open error:%s\n", err)
		return
	}
	testDefAcc, err = testWallet.GetDefaultAccount(testPasswd)
	if err != nil {
		fmt.Printf("GetDefaultAccount err: %s\n", err)
		return
	}
	testVcStatusSdk = NewVcStatusSdk(testRpcUrl)
	testContractAddr, err = utils.GetContractAddress(CredentialCode)
	if err != nil {
		fmt.Printf("GetContractAddress err: %s\n", err)
		return
	}
}

func FileExisted(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil || os.IsExist(err)
}

type credentialSub struct {
	Id     string `json:"id,omitempty"`
	Degree string `json:"degree,omitempty"`
}

func PackVC() (*vc.VerifiableCredential, error) {
	contexts := []string{"https://www.w3.org/2018/credentials/examples/v1"}
	credentialId := "http://example.edu/credentials/58473"
	types := []string{"AlumniCredential"}
	credentialSubject := credentialSub{
		Id:     "did:example:ebfeb1f712ebc6f1c276e12ec21",
		Degree: "123",
	}
	issuanceTime := int64(1637549615)
	expirationDateTimestamp := int64(0)
	issuerId := "did:ont:ebfeb1f712ebc6f1c276e12ec21"
	return vc.PackCredential(contexts, credentialId, types, credentialSubject, issuerId, nil, issuanceTime, expirationDateTimestamp)
}

func CreateCredential(pri keypair.PrivateKey, pub keypair.PublicKey) (*vc.VerifiableCredential, error) {
	packVc, err := PackVC()
	if err != nil {
		return nil, err
	}
	pk := &vc.PublicKey{
		Id:           "",
		Type:         "SHA256withECDSA",
		PublicKeyHex: hex.EncodeToString(keypair.SerializePublicKey(pub)),
	}
	proof, err := vc.PackCredentialProof(packVc, time.Now().UTC().Unix(), vc.PROOF_PURPOSE, pk, pri)
	if err != nil {
		return nil, err
	}
	return vc.CreateVC(packVc, proof)
}

//./ontology --testmode --testmode-gen-block-time 10
func TestVcStatusSdk_GetPublicKeyFromDID(t *testing.T) {
	issuer, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	assert.Nil(t, err)
	txHash, err := testVcStatusSdk.ontSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, testDefAcc, issuer.ID, testDefAcc)
	assert.Nil(t, err)
	t.Logf("hash:%s", txHash.ToHexString())
	_, err = testVcStatusSdk.ontSdk.WaitForGenerateBlock(10*time.Second, 1)
	assert.Nil(t, err)
	keyId := issuer.ID + "#keys-1"
	publicKey, err := testVcStatusSdk.GetPublicKeyFromDID(issuer.ID, keyId)
	assert.Nil(t, err)
	t.Logf("publicKey:%v", publicKey)
}

func TestVcStatusSdk_Register_RevokeVCOnChain(t *testing.T) {
	issuer, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	assert.Nil(t, err)
	holder, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	assert.Nil(t, err)
	txHash, err := testVcStatusSdk.ontSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, testDefAcc, issuer.ID, testDefAcc)
	assert.Nil(t, err)
	t.Logf("txHash:%s", txHash.ToHexString())
	_, err = testVcStatusSdk.ontSdk.WaitForGenerateBlock(10*time.Second, 1)
	assert.Nil(t, err)
	contractHash, err := testVcStatusSdk.ontSdk.NeoVM.DeployNeoVMSmartContract(testGasPrice, 20400000, testDefAcc, false, CredentialCode, "cred", "1.0", "auth", "", "")
	assert.Nil(t, err)
	t.Logf("contractHash:%s", contractHash.ToHexString())
	_, err = testVcStatusSdk.ontSdk.WaitForGenerateBlock(10*time.Second, 1)
	assert.Nil(t, err)
	registerHash, err := testVcStatusSdk.RegisterVCOnChain(testContractAddr.ToHexString(), "", issuer.ID, holder.ID, testGasPrice, testGasLimit, testDefAcc, testDefAcc)
	assert.Nil(t, err)
	t.Logf("registerHash:%v", registerHash)
	_, err = testVcStatusSdk.ontSdk.WaitForGenerateBlock(30 * time.Second)
	assert.Nil(t, err)
	hash, err := testVcStatusSdk.ontSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, testDefAcc, holder.ID, testDefAcc)
	assert.Nil(t, err)
	t.Logf("hash:%s", hash.ToHexString())
	_, err = testVcStatusSdk.ontSdk.WaitForGenerateBlock(10*time.Second, 1)
	assert.Nil(t, err)
	revokeHash, err := testVcStatusSdk.RevokeVCOnChain(testContractAddr.ToHexString(), "", issuer.ID, holder.ID, testGasPrice, testGasLimit, testDefAcc, testDefAcc)
	assert.Nil(t, err)
	t.Logf("hash:%v", revokeHash)
}

func TestVcStatusSdk_GetVCStatusOnChain(t *testing.T) {
	credential, err := CreateCredential(testDefAcc.PrivateKey, testDefAcc.PublicKey)
	assert.Nil(t, err)
	issuer, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	assert.Nil(t, err)
	holder, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	assert.Nil(t, err)
	txHash, err := testVcStatusSdk.ontSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, testDefAcc, issuer.ID, testDefAcc)
	assert.Nil(t, err)
	t.Logf("hash:%s", txHash.ToHexString())
	_, err = testVcStatusSdk.ontSdk.WaitForGenerateBlock(10*time.Second, 1)
	assert.Nil(t, err)
	contractHash, err := testVcStatusSdk.ontSdk.NeoVM.DeployNeoVMSmartContract(testGasPrice, 20400000, testDefAcc, false, CredentialCode, "cred", "1.0", "auth", "", "")
	assert.Nil(t, err)
	t.Logf("contractHash:%s", contractHash.ToHexString())
	_, err = testVcStatusSdk.ontSdk.WaitForGenerateBlock(30 * time.Second)
	assert.Nil(t, err)
	registerHash, err := testVcStatusSdk.RegisterVCOnChain(testContractAddr.ToHexString(), "", issuer.ID, holder.ID, testGasPrice, testGasLimit, testDefAcc, testDefAcc)
	assert.Nil(t, err)
	t.Logf("registerHash:%v", registerHash)
	_, err = testVcStatusSdk.ontSdk.WaitForGenerateBlock(30 * time.Second)
	assert.Nil(t, err)
	res, err := testVcStatusSdk.GetVCStatusOnChain(testContractAddr.ToHexString(), credential)
	assert.Nil(t, err)
	t.Logf("res:%v", res)
}
