package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"chainmaker.org/chainmaker/contract-sdk-go/v2/sdk"
)

const (
	keyDid          = "d" // 此为存入数据库的世界状态key，故越短越好
	keyIndexPubKey  = "p"
	keyIndexAddress = "a"
	keyAdmin        = "Admin"
)

var (
	errDidNotFound      = errors.New("did not found")
	errTemplateNotFound = errors.New("template not found")
	errDataNotFound     = errors.New("data not found")
)

// Dal 数据库访问层
type Dal struct {
}

// Db 获取数据库实例
func (dal *Dal) Db() sdk.SDKInterface {
	return sdk.Instance
}
func processDid4Key(did string) string {
	if len(did) > 9 {
		did = did[9:] //去掉did:cnbn:
	}
	return strings.ReplaceAll(did, ":", "_")
}
func processPubKey4Key(pubKey string) string {
	hash := sha256.Sum256([]byte(pubKey))
	return hex.EncodeToString(hash[:])
}

func (dal *Dal) putDidDocument(did string, didDocument []byte) error {
	//将DID Document存入数据库
	err := dal.Db().PutStateByte(keyDid, processDid4Key(did), didDocument)
	if err != nil {
		return err
	}
	return nil
}
func (dal *Dal) getDidDocument(did string) ([]byte, error) {
	//从数据库中获取DID Document
	didDocument, err := dal.Db().GetStateByte(keyDid, processDid4Key(did))
	if err != nil {
		return nil, err
	}
	if len(didDocument) == 0 {
		return nil, errDidNotFound
	}
	return didDocument, nil
}

func (dal *Dal) putIndexPubKey(pubKey string, did string) error {
	//将索引存入数据库
	err := dal.Db().PutStateByte(keyIndexPubKey, processPubKey4Key(pubKey), []byte(did))
	if err != nil {
		return err
	}
	return nil
}
func (dal *Dal) deleteIndexPubKey(pubKey string) error {
	//从数据库中删除索引
	err := dal.Db().DelState(keyIndexPubKey, processPubKey4Key(pubKey))
	if err != nil {
		return err
	}
	return nil
}

func (dal *Dal) getDidByPubKey(pubKey string) (string, error) {
	//从数据库中获取索引
	did, err := dal.Db().GetStateByte(keyIndexPubKey, processPubKey4Key(pubKey))
	if err != nil {
		return "", err
	}
	if len(did) == 0 {
		return "", errDidNotFound
	}
	return string(did), nil
}

func (dal *Dal) putIndexAddress(address string, did string) error {
	//将索引存入数据库
	err := dal.Db().PutStateByte(keyIndexAddress, address, []byte(did))
	if err != nil {
		return err
	}
	return nil
}

func (dal *Dal) deleteIndexAddress(address string) error {
	//从数据库中删除索引
	err := dal.Db().DelState(keyIndexAddress, address)
	if err != nil {
		return err
	}
	return nil
}

func (dal *Dal) getDidByAddress(address string) (string, error) {
	//从数据库中获取索引
	did, err := dal.Db().GetStateByte(keyIndexAddress, address)
	if err != nil {
		return "", err
	}
	if len(did) == 0 {
		return "", errDidNotFound
	}
	return string(did), nil
}

func (dal *Dal) putAdmin(admin string) error {
	//将Admin存入数据库
	err := dal.Db().PutStateFromKey(keyAdmin, admin)
	if err != nil {
		return err
	}
	return nil
}
func (dal *Dal) getAdmin() (string, error) {
	//从数据库中获取Admin
	admin, err := dal.Db().GetStateFromKey(keyAdmin)
	if err != nil || len(admin) == 0 {
		return "", errDataNotFound
	}
	return admin, nil
}
