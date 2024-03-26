package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"chainmaker.org/chainmaker/common/v2/crypto/asym"
	"github.com/buger/jsonparser"
	//"github.com/square/go-jose"
	"github.com/xeipuuv/gojsonschema"
)

const proof = "proof"

// GetDidDocument 根据DID URL获取DID文档
type GetDidDocument func(did string) (*DIDDocument, error)

// Proof DID文档或者凭证的证明
type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	ProofPurpose       string `json:"proofPurpose"`
	Challenge          string `json:"challenge,omitempty"`
	VerificationMethod string `json:"verificationMethod"`
	ProofValue         string `json:"proofValue,omitempty"`
}

// DIDDocument DID文档
type DIDDocument struct {
	rawData            json.RawMessage
	Context            string   `json:"@context"`
	ID                 string   `json:"id"`
	Controller         []string `json:"controller"`
	Created            string   `json:"created,omitempty"`
	Updated            string   `json:"updated,omitempty"`
	VerificationMethod []struct {
		ID           string `json:"id"`
		PublicKeyPem string `json:"publicKeyPem"`
		Controller   string `json:"controller"`
		Address      string `json:"address"`
	} `json:"verificationMethod"`
	Service []struct {
		ID              string `json:"id"`
		Type            string `json:"type"`
		ServiceEndpoint string `json:"serviceEndpoint"`
	} `json:"service,omitempty"`
	Authentication []string        `json:"authentication"`
	Proof          json.RawMessage `json:"proof,omitempty"`
}

// DocProof DID文档的证明
type DocProof struct {
	Single *Proof
	Array  []*Proof
}

func parseProof(raw json.RawMessage) (DocProof, error) {
	var docProof DocProof
	var single Proof
	var array []*Proof

	if err := json.Unmarshal(raw, &single); err == nil {
		docProof.Single = &single
		return docProof, nil
	}

	if err := json.Unmarshal(raw, &array); err == nil {
		docProof.Array = array
		return docProof, nil
	}

	return docProof, fmt.Errorf("unable to parse proof")
}

// compactJson 压缩json字符串，去掉空格换行等
func compactJson(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	err := json.Compact(&buf, raw)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// NewDIDDocument 根据DID文档json字符串创建DID文档
func NewDIDDocument(didDocumentJson string) *DIDDocument {
	var didDocument DIDDocument
	err := json.Unmarshal([]byte(didDocumentJson), &didDocument)
	if err != nil {
		return nil
	}
	//fmt.Println("didDocument", didDocument)
	didDocument.rawData = []byte(didDocumentJson)
	return &didDocument
}

// GetProofs 获取DID文档的证明，无论是一个Proof还是多个，都返回数组
func (didDoc *DIDDocument) GetProofs() []*Proof {
	if didDoc.Proof == nil {
		return nil
	}
	docProof, err := parseProof(didDoc.Proof)
	if err != nil {
		return nil
	}
	if docProof.Single != nil {
		return []*Proof{docProof.Single}
	}
	if len(docProof.Array) != 0 {
		return docProof.Array
	}
	return nil
}

// VerifySignature 验证DID文档的签名
func (didDoc *DIDDocument) VerifySignature(getDidDocument GetDidDocument) (bool, error) {
	if didDoc.Proof == nil {
		return false, fmt.Errorf("didDoc.Proof is nil")
	}
	docProof, err := parseProof(didDoc.Proof)
	if err != nil {
		return false, err
	}
	if docProof.Single != nil {
		return didDoc.verifySignature(getDidDocument, docProof.Single)
	}
	if len(docProof.Array) != 0 {
		for _, proof := range docProof.Array {
			pass, err := didDoc.verifySignature(getDidDocument, proof)
			if err != nil {
				return false, err
			}
			if !pass {
				return false, nil
			}
		}
	}
	return false, fmt.Errorf("didDoc.Proof is invalid")
}
func (didDoc *DIDDocument) verifySignature(getDidDocument GetDidDocument, p *Proof) (bool, error) {
	//删除proof字段
	withoutProof := jsonparser.Delete(didDoc.rawData, proof)
	//去掉空格换行等
	withoutProof, err := compactJson(withoutProof)
	if err != nil {
		return false, err
	}
	return verifySignature(getDidDocument, p, withoutProof)
}

func verifySignature(getDidDocument GetDidDocument, proof *Proof, withoutProofJson []byte) (bool, error) {
	vm := proof.VerificationMethod
	signerDid := vm[0:strings.Index(vm, "#")]
	signerDidDocument, err := getDidDocument(signerDid)
	if err != nil {
		return false, err
	}
	var pkPem string
	for _, pk := range signerDidDocument.VerificationMethod {
		if pk.ID == vm {
			pkPem = pk.PublicKeyPem
			break
		}
	}
	if pkPem == "" {
		return false, fmt.Errorf("pkPem is empty")
	}
	pubKey, err := asym.PublicKeyFromPEM([]byte(pkPem))
	if err != nil {
		return false, err
	}

	//如果是Base64编码后的签名
	if len(proof.ProofValue) > 0 {
		//base64 decode didDoc.Proof.ProofValue
		signature, err := base64.StdEncoding.DecodeString(proof.ProofValue)
		if err != nil {
			return false, err
		}
		pass, err := pubKey.Verify(withoutProofJson, signature)
		if err != nil {
			return false, err
		}
		return pass, nil
	}

	return false, fmt.Errorf("Proof.ProofValue and Proof.Jws are both empty")

}

// VerifiableCredential VC凭证，证书
type VerifiableCredential struct {
	rawData           json.RawMessage
	Context           []string               `json:"@context"`
	ID                string                 `json:"id"`
	Type              []string               `json:"type"`
	Issuer            string                 `json:"issuer"`
	IssuanceDate      string                 `json:"issuanceDate"`
	ExpirationDate    string                 `json:"expirationDate"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	Template          *struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Version string `json:"version"`
		VcType  string `json:"vcType"`
	} `json:"template,omitempty"`
	Proof *Proof `json:"proof,omitempty"`
}

// NewVerifiableCredential 根据VC凭证json字符串创建VC凭证
func NewVerifiableCredential(vcJson string) *VerifiableCredential {
	var vc VerifiableCredential
	err := json.Unmarshal([]byte(vcJson), &vc)
	if err != nil {
		return nil
	}
	vc.rawData = []byte(vcJson)
	return &vc
}

// GetCredentialSubjectID 获取VC凭证的持有者DID
func (vc *VerifiableCredential) GetCredentialSubjectID() string {
	return vc.CredentialSubject["id"].(string)
}

// VerifySignature 验证VC凭证的签名
func (vc *VerifiableCredential) VerifySignature(getDidDocument GetDidDocument) (bool, error) {
	withoutProof := jsonparser.Delete(vc.rawData, proof)
	//去掉空格换行等
	withoutProof, err := compactJson(withoutProof)
	if err != nil {
		return false, err
	}
	return verifySignature(getDidDocument, vc.Proof, withoutProof)
}

// VerifyVcTemplateContent 验证VC凭证的内容是否符合模板
func (vc *VerifiableCredential) VerifyVcTemplateContent(vcTemplate string) (bool, error) {
	if len(vcTemplate) == 0 {
		return false, fmt.Errorf("vcTemplate is empty")
	}
	schemaLoader := gojsonschema.NewStringLoader(vcTemplate)
	data, _ := json.Marshal(vc.CredentialSubject)
	dataLoader := gojsonschema.NewStringLoader(string(data))

	result, err := gojsonschema.Validate(schemaLoader, dataLoader)
	if err != nil {
		return false, err
	}

	if result.Valid() {
		return true, nil
	}
	errMsg := "Invalid credentialSubject, errors:"
	for _, desc := range result.Errors() {
		errMsg += fmt.Sprintf("- %s\n", desc)
	}
	return false, fmt.Errorf(errMsg)

}

// VerifiablePresentation VP持有者展示的凭证
type VerifiablePresentation struct {
	rawData              json.RawMessage
	Context              []string               `json:"@context"`
	Type                 string                 `json:"type"`
	ID                   string                 `json:"id"`
	VerifiableCredential []VerifiableCredential `json:"verifiableCredential"`
	PresentationUsage    string                 `json:"presentationUsage,omitempty"`
	ExpirationDate       string                 `json:"expirationDate,omitempty"`
	Verifier             string                 `json:"verifier,omitempty"`
	Proof                *Proof                 `json:"proof,omitempty"`
}

// NewVerifiablePresentation 根据VP持有者展示的凭证json字符串创建VP持有者展示的凭证
func NewVerifiablePresentation(vpJson string) *VerifiablePresentation {
	var vp VerifiablePresentation
	err := json.Unmarshal([]byte(vpJson), &vp)
	if err != nil {
		return nil
	}
	vp.rawData = []byte(vpJson)
	return &vp
}

// VerifySignature 验证VP持有者展示的凭证的签名
func (vp *VerifiablePresentation) VerifySignature(getDidDocument GetDidDocument) (bool, error) {
	withoutProof := jsonparser.Delete(vp.rawData, proof)
	//去掉空格换行等
	withoutProof, err := compactJson(withoutProof)
	if err != nil {
		return false, err
	}
	return verifySignature(getDidDocument, vp.Proof, withoutProof)
}
