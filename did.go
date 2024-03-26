package main

import (
	"chainmaker.org/chainmaker/contract-sdk-go/v2/sdk"
	"errors"
	"github.com/buger/jsonparser"
)

const (
	didMethod = "cnbn"
)

var (
	errInvalidDid = errors.New("invalid did")
)

// DidContract 存证合约实现
type DidContract struct {
	dal *Dal
}

// NewDidContract 创建存证合约实例
func NewDidContract() *DidContract {
	return &DidContract{
		dal: &Dal{},
	}
}

// InitAdmin 设置合约管理员
func (e *DidContract) InitAdmin(didJson string) error {
	didDoc := NewDIDDocument(didJson)
	if didDoc == nil {
		return errors.New("invalid did document")
	}
	err := e.addDidDocument(didDoc, false)
	if err != nil {
		return err
	}
	adminDid := didDoc.ID
	if err != nil {
		return err
	}
	err = e.dal.putAdmin(adminDid)
	if err != nil {
		return err
	}
	return nil
}

// SetAdmin 修改合约管理员
func (e *DidContract) SetAdmin(did string) error {
	//检查sender是否是admin
	if !e.isAdmin() {
		return errors.New("only admin can set admin")
	}
	//检查did是否有效
	valid, err := e.IsValidDid(did)
	if err != nil {
		return err
	}
	if !valid {
		return errInvalidDid
	}
	//保存admin
	err = e.dal.putAdmin(did)
	if err != nil {
		return err
	}
	return nil
}

// GetAdmin 获取合约管理员DID
func (e *DidContract) GetAdmin() (string, error) {
	return e.dal.getAdmin()
}

// IsValidDid 判断DID URL是否合法
func (e *DidContract) IsValidDid(did string) (bool, error) {
	if len(did) < 9 {
		return false, errInvalidDid
	}
	//check did method
	if did[4:4+len(didMethod)] != didMethod {
		return false, errors.New("invalid did method")
	}
	//检查DID Document是否存在
	didDocumentJson, err := e.dal.getDidDocument(did)
	if err != nil || len(didDocumentJson) == 0 {
		return false, errDidNotFound
	}
	return true, nil
}

func (e *DidContract) isAdmin() bool {
	senderDid, err := e.getSenderDid()
	if err != nil {
		return false
	}
	adminDid, err := e.dal.getAdmin()
	if err != nil {
		return false
	}
	return senderDid == adminDid
}

func (e *DidContract) getSenderDid() (string, error) {
	sender, err := sdk.Instance.Origin()
	if err != nil {
		return "", err
	}
	return e.dal.getDidByAddress(sender)
}

func (e *DidContract) getDidDocument(did string) (*DIDDocument, error) {
	didDocumentJson, err := e.dal.getDidDocument(did)
	if err != nil || len(didDocumentJson) == 0 {
		return nil, errors.New("did document not found, did=" + did)
	}
	didDoc := NewDIDDocument(string(didDocumentJson))
	if didDoc == nil {
		return nil, errors.New("invalid did document")
	}
	return didDoc, nil
}

func (e *DidContract) verifyDidDocument(didDoc *DIDDocument) error {
	//检查DID Document有效性
	if didDoc == nil {
		return errors.New("invalid did document")
	}
	did, pubKeys, address, err := parsePubKeyAddress(didDoc)

	for _, pk := range pubKeys {
		//检查公钥是否存在
		dbDid, _ := e.dal.getDidByPubKey(pk)
		if len(dbDid) > 0 && dbDid != did {
			return errors.New("public key already exists")
		}
	}
	for _, addr := range address {
		//检查地址是否存在
		dbDid, _ := e.dal.getDidByAddress(addr)
		if len(dbDid) > 0 && dbDid != did {
			return errors.New("address already exists")
		}
	}

	if err != nil {
		return err
	}
	//check did method
	if did[4:4+len(didMethod)] != didMethod {
		return errors.New("invalid did method")
	}
	//check did document signature
	if didDoc.Proof == nil {
		return errors.New("invalid did document, need proof")
	}
	pass, err := didDoc.VerifySignature(func(_did string) (*DIDDocument, error) {
		//如果是DID用户自己签名，那么DID Document还没有上链，直接返回didDoc
		if _did == did {
			return didDoc, nil
		}
		return e.getDidDocument(_did)
	})

	if err != nil {
		return err
	}

	if !pass {
		return errors.New("invalid did document signature")
	}
	return nil
}

// AddDidDocument 添加DID Document
func (e *DidContract) AddDidDocument(didDocument string) error {
	didDoc := NewDIDDocument(didDocument)
	if didDoc == nil {
		return errors.New("invalid did document")
	}
	err := e.verifyDidDocument(didDoc)
	if err != nil {
		return err
	}
	//存储DID Document
	return e.addDidDocument(didDoc, true)
}
func (e *DidContract) addDidDocument(didDoc *DIDDocument, checkExist bool) error {
	if checkExist {
		//检查DID Document是否存在
		dbDidDoc, _ := e.dal.getDidDocument(didDoc.ID)
		if len(dbDidDoc) != 0 {
			return errors.New("did document already exists")
		}
	}
	did, pubKeys, addresses, err := parsePubKeyAddress(didDoc)
	if err != nil {
		return err
	}
	//在存储DID文档到状态数据库时，不需要Proof信息
	withoutProof := jsonparser.Delete(didDoc.rawData, proof)
	//压缩DID Document，去掉空格和换行符
	compactDidDoc, err := compactJson(withoutProof)
	if err != nil {
		return err
	}
	//Save did document
	err = e.dal.putDidDocument(did, compactDidDoc)
	if err != nil {
		return err
	}
	//Save pubkey index
	for _, pk := range pubKeys {
		err = e.dal.putIndexPubKey(pk, did)
		if err != nil {
			return err
		}
	}
	//save address index
	for _, addr := range addresses {
		err = e.dal.putIndexAddress(addr, did)
		if err != nil {
			return err
		}
	}
	return nil
}

func parsePubKeyAddress(didDoc *DIDDocument) (didUrl string, pubKeys []string, addresses []string, err error) {
	pubKeys = make([]string, 0)
	addresses = make([]string, 0)
	for _, pk := range didDoc.VerificationMethod {
		pubKeys = append(pubKeys, pk.PublicKeyPem)
		addresses = append(addresses, pk.Address)
	}
	return didDoc.ID, pubKeys, addresses, nil

}

// GetDidDocument 获取DID Document
func (e *DidContract) GetDidDocument(did string) (string, error) {
	// check did valid
	valid, err := e.IsValidDid(did)
	if err != nil {
		return "", err
	}
	if !valid {
		return "", errors.New("invalid did")
	}
	didDoc, err := e.dal.getDidDocument(did)
	if err != nil {
		return "", err
	}
	return string(didDoc), nil
}

// GetDidByPubkey 根据公钥获取DID
func (e *DidContract) GetDidByPubkey(pk string) (string, error) {
	//get did by pubkey
	did, err := e.dal.getDidByPubKey(pk)
	if err != nil {
		return "", err
	}

	return did, nil
}

// GetDidDocumentByPubkey 根据公钥获取DID Document
func (e *DidContract) GetDidDocumentByPubkey(pk string) (string, error) {
	//get did by pubkey
	did, err := e.dal.getDidByPubKey(pk)
	if err != nil {
		return "", err
	}
	//get did document
	return e.GetDidDocument(did)
}

// GetDidByAddress 根据地址获取DID
func (e *DidContract) GetDidByAddress(address string) (string, error) {
	//get did by address
	return e.dal.getDidByAddress(address)
}

// GetDidDocumentByAddress 根据地址获取DID Document
func (e *DidContract) GetDidDocumentByAddress(address string) (string, error) {
	//get did by address
	did, err := e.dal.getDidByAddress(address)
	if err != nil {
		return "", err
	}
	//get did document
	return e.GetDidDocument(did)
}

// UpdateDidDocument 更新DID Document
func (e *DidContract) UpdateDidDocument(didDocument string) error {
	didDoc := NewDIDDocument(didDocument)
	if didDoc == nil {
		return errors.New("invalid did document")
	}
	//判断SenderDID是不是DID Document的创建者
	senderDid, err := e.getSenderDid()
	if err != nil {
		return err
	}
	if senderDid != didDoc.ID {
		if !e.isAdmin() {
			return errors.New("only admin or did owner can update did document")
		}
	}
	//检查新DID Document有效性
	err = e.verifyDidDocument(didDoc)
	if err != nil {
		return err
	}
	//检查DID Document是否存在
	did, pubKeys, addresses, err := parsePubKeyAddress(didDoc)
	if err != nil {
		return err
	}
	//根据DID查询已有的DID Document，并删除Index
	oldDidDocument, err := e.dal.getDidDocument(did)
	if err != nil {
		return err
	}
	oldDidDoc := NewDIDDocument(string(oldDidDocument))
	_, oldPubKeys, oldAddresses, _ := parsePubKeyAddress(oldDidDoc)
	//如果oldPubKeys在新的pubKeys中不存在，则删除
	for _, oldPk := range oldPubKeys {
		if !isInList(oldPk, pubKeys) {
			err = e.dal.deleteIndexPubKey(oldPk)
			if err != nil {
				return err
			}
		}
	}
	//如果oldAddresses在新的addresses中不存在，则删除
	for _, oldAddr := range oldAddresses {
		if !isInList(oldAddr, addresses) {
			err = e.dal.deleteIndexAddress(oldAddr)
			if err != nil {
				return err
			}
		}
	}
	//压缩DID Document，去掉空格和换行符
	compactDidDoc, err := compactJson([]byte(didDocument))
	if err != nil {
		return err
	}
	//保存新的DID Document
	err = e.dal.putDidDocument(did, compactDidDoc)
	if err != nil {
		return err
	}
	//保存新的pubKeys
	for _, pk := range pubKeys {
		if !isInList(pk, oldPubKeys) {
			err = e.dal.putIndexPubKey(pk, did)
			if err != nil {
				return err
			}
		}
	}
	//保存新的addresses
	for _, addr := range addresses {
		if !isInList(addr, oldAddresses) {
			err = e.dal.putIndexAddress(addr, did)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func isInList(pk string, keys []string) bool {
	for _, k := range keys {
		if k == pk {
			return true
		}
	}
	return false
}
