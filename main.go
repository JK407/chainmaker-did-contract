package main

import (
	"encoding/json"
	"fmt"
	"strconv"

	"chainmaker.org/chainmaker/contract-sdk-go/v2/pb/protogo"
	"chainmaker.org/chainmaker/contract-sdk-go/v2/sandbox"
	"chainmaker.org/chainmaker/contract-sdk-go/v2/sdk"
	"chainmaker.org/chainmaker/contract-utils/safemath"
	"chainmaker.org/chainmaker/contract-utils/standard"
)

func main() {
	err := sandbox.Start(&MainContract{c: NewDidContract()})
	if err != nil {
		sdk.Instance.Errorf(err.Error())
	}
}

// DidContractAll 长安链DID合约go接口
type DidContractAll interface {
	InitAdmin(didJson string) error
	SetAdmin(did string) error
	GetAdmin() (string, error)
	IsValidDid(did string) (bool, error)
	AddDidDocument(didDocument string) error
	GetDidDocument(did string) (string, error)
	GetDidByPubkey(pk string) (string, error)
	GetDidByAddress(address string) (string, error)
	UpdateDidDocument(didDocument string) error
}

// MainContract 长安链DID主入口合约
type MainContract struct {
	c DidContractAll
}

// InitContract install contract func
func (e *MainContract) InitContract() protogo.Response {
	adminDidDoc, err := RequireString("didDocument")
	if err != nil {
		return sdk.Error(err.Error())
	}
	return Return(e.c.InitAdmin(adminDidDoc))
}

// UpgradeContract upgrade contract func
func (e *MainContract) UpgradeContract() protogo.Response {
	//在升级合约的时候，可以重新设置新的管理员，也可以不设置
	adminDidDoc := OptionString("didDocument")
	if len(adminDidDoc) > 0 {
		return Return(e.c.InitAdmin(adminDidDoc))
	}
	return sdk.SuccessResponse
}

// InvokeContract the entry func of invoke contract func
func (e *MainContract) InvokeContract(method string) (result protogo.Response) { //nolint
	// 记录异常结果日志
	defer func() {
		if result.Status != 0 {
			sdk.Instance.Warnf(result.Message)
		}
	}()

	switch method {
	case "SetAdmin":
		adminDid, err := RequireString("did")
		if err != nil {
			return sdk.Error(err.Error())
		}
		return Return(e.c.SetAdmin(adminDid))
	case "GetAdmin":
		return ReturnString(e.c.GetAdmin())
	case "IsValidDid":
		did, err := RequireString("did")
		if err != nil {
			return sdk.Error(err.Error())
		}
		return ReturnBool(e.c.IsValidDid(did))
	case "AddDidDocument":
		didDocument, err := RequireString("didDocument")
		if err != nil {
			return sdk.Error(err.Error())
		}
		return Return(e.c.AddDidDocument(didDocument))
	case "GetDidDocument":
		did, err := RequireString("did")
		if err != nil {
			return sdk.Error(err.Error())
		}
		return ReturnString(e.c.GetDidDocument(did))
	case "GetDidByPubkey":
		pubKey, err := RequireString("pubKey")
		if err != nil {
			return sdk.Error(err.Error())
		}
		return ReturnString(e.c.GetDidByPubkey(pubKey))
	case "GetDidByAddress":
		address, err := RequireString("address")
		if err != nil {
			return sdk.Error(err.Error())
		}
		return ReturnString(e.c.GetDidByAddress(address))
	case "UpdateDidDocument":
		didDocument, err := RequireString("didDocument")
		if err != nil {
			return sdk.Error(err.Error())
		}
		return Return(e.c.UpdateDidDocument(didDocument))
	}

	return sdk.Error("invalid method:" + method)
}

////////////////////////////////Helper//////////////////////////////////

// ReturnUint256 封装返回SafeUint256类型为Response，如果有error则忽略num，封装error
// @param num
// @param err
// @return Response
func ReturnUint256(num *safemath.SafeUint256, err error) protogo.Response {
	if err != nil {
		return sdk.Error(err.Error())
	}
	return sdk.Success([]byte(num.ToString()))
}

// ReturnString 封装返回string类型为Response，如果有error则忽略str，封装error
// @param str
// @param err
// @return Response
func ReturnString(str string, err error) protogo.Response {
	if err != nil {
		return sdk.Error(err.Error())
	}
	return sdk.Success([]byte(str))
}
func ReturnStrings(str string, err error) protogo.Response {
	if err != nil {
		return sdk.Error(err.Error())
	}
	return sdk.Success([]byte(str))
}

// ReturnBytes 封装返回[]byte类型为Response，如果有error则忽略str，封装error
func ReturnBytes(str []byte, err error) protogo.Response {
	if err != nil {
		return sdk.Error(err.Error())
	}
	return sdk.Success(str)
}

// ReturnJson 封装返回interface类型为json string Response
// @param data
// @return Response
func ReturnJson(data interface{}, err error) protogo.Response {
	if err != nil {
		return sdk.Error(err.Error())
	}
	standardsBytes, err := json.Marshal(data)
	if err != nil {
		return sdk.Error(err.Error())
	}
	return sdk.Success(standardsBytes)
}

// Return 封装返回Bool类型为Response，如果有error则忽略bool，封装error
// @param err
// @return Response
func Return(err error) protogo.Response {
	if err != nil {
		return sdk.Error(err.Error())
	}
	return sdk.SuccessResponse
}

// ReturnUint8 封装返回uint8类型为Response，如果有error则忽略num，封装error
// @param num
// @param err
// @return Response
func ReturnUint8(num uint8, err error) protogo.Response {
	if err != nil {
		return sdk.Error(err.Error())
	}
	return sdk.Success([]byte(strconv.Itoa(int(num))))
}

// ReturnBool 封装返回bool类型为Response，如果有error则忽略bool，封装error
func ReturnBool(b bool, e error) protogo.Response {
	if e != nil {
		return sdk.Error(e.Error())
	}
	if b {
		return sdk.Success([]byte(standard.TrueString))
	}
	return sdk.Success([]byte(standard.FalseString))
}

// RequireString 必须要有参数 string类型
// @param key
// @return string
// @return error
func RequireString(key string) (string, error) {
	args := sdk.Instance.GetArgs()
	b, ok := args[key]
	if !ok || len(b) == 0 {
		return "", fmt.Errorf("CMDID: require parameter:'%s'", key)
	}
	return string(b), nil
}

// RequireStrings 必须要有参数 []string类型
func RequireStrings(key string) ([]string, error) {
	args := sdk.Instance.GetArgs()
	b, ok := args[key]
	if !ok || len(b) == 0 {
		return nil, fmt.Errorf("CMDID: require parameter:'%s'", key)
	}
	var strs []string
	err := json.Unmarshal(b, &strs)
	if err != nil {
		return nil, err
	}
	return strs, nil
}

// RequireString2 必须要有参数key1 单个string或者key2 []string类型
func RequireString2(key1, key2 string) ([]string, error) {
	args := sdk.Instance.GetArgs()
	b, ok := args[key2]
	if !ok || len(b) == 0 {
		b1, ok1 := args[key1]
		if !ok1 || len(b1) == 0 {
			return nil, fmt.Errorf("CMDID: require parameter:'%s' or '%s'", key1, key2)
		}
		return []string{string(b1)}, nil
	}
	var strs []string
	err := json.Unmarshal(b, &strs)
	if err != nil {
		return nil, err
	}
	return strs, nil
}

// RequireUint256 必须要有参数 Uint256类型
// @param key
// @return *safemath.SafeUint256
// @return error
func RequireUint256(key string) (*safemath.SafeUint256, error) {
	args := sdk.Instance.GetArgs()
	b, ok := args[key]
	if !ok {
		return nil, fmt.Errorf("CMDID: require parameter:'%s'", key)
	}
	num, ok := safemath.ParseSafeUint256(string(b))
	if !ok {
		return nil, fmt.Errorf("CMDID: parameter:'%s' not a valid uint256", key)
	}
	return num, nil
}

// RequireUint256s 必须要有参数 []*safemath.SafeUint256类型
func RequireUint256s(key string) ([]*safemath.SafeUint256, error) {
	args := sdk.Instance.GetArgs()
	b, ok := args[key]
	if !ok {
		return nil, fmt.Errorf("CMDID: require parameter:'%s'", key)
	}
	var nums []*safemath.SafeUint256
	err := json.Unmarshal(b, &nums)
	if err != nil {
		return nil, err
	}
	return nums, nil
}

// OptionInt 获取可选参数 int类型，没有则返回defaultValue
func OptionInt(key string, defaultValue int) int {
	args := sdk.Instance.GetArgs()
	b, ok := args[key]
	if !ok {
		return defaultValue
	}
	num, err := strconv.Atoi(string(b))
	if err != nil {
		return defaultValue
	}
	return num
}

// OptionTime 获取可选参数 int64类型时间戳，没有则返回0
func OptionTime(key string) int64 {
	args := sdk.Instance.GetArgs()
	b, ok := args[key]
	if !ok {
		return 0
	}
	t, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return 0
	}
	return t
}

// OptionString 获取可选参数 string类型
func OptionString(key string) string {
	args := sdk.Instance.GetArgs()
	b, ok := args[key]
	if !ok {
		return ""
	}
	return string(b)
}
