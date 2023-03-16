// Copyright 2022 Teamgram Authors
//  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author: teamgramio (teamgram.io@gmail.com)
//
/**
这段代码实现了一个名为authKeyUtil的类型，其中包含了一些操作AuthKey的方法。具体来说，它包括以下方法：

newAuthKeyUtil：用于创建authKeyUtil实例，并初始化keyData和key属性。
Equal：用于比较两个authKeyUtil实例是否相等。
AuthKeyId：返回keyData中的AuthKeyId属性。
AuthKeyType：返回keyData中的AuthKeyType属性。
PermAuthKeyId：返回keyData中的PermAuthKeyId属性。
TempAuthKeyId：返回keyData中的TempAuthKeyId属性。
MediaTempAuthKeyId：返回keyData中的MediaTempAuthKeyId属性。
AesIgeEncrypt：使用AES-IGE算法对原始数据进行加密。
AesIgeDecrypt：使用AES-IGE算法对消息密钥和原始数据进行解密。
此外，该代码还导入了mtproto和crypto包。主要功能是用于MTProto协议中的身份验证和加密解密操作。
*/
// 包server提供了处理服务端逻辑所需的功能
package server

import (
	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/proto/mtproto/crypto"
)

// authKeyUtil用于操作AuthKey
type authKeyUtil struct {
	keyData *mtproto.AuthKeyInfo // 存储AuthKey信息的结构体
	key     *crypto.AuthKey      // 存储加密密钥和解密密钥的结构体
}

// newAuthKeyUtil创建authKeyUtil实例，并初始化keyData和key属性
func newAuthKeyUtil(k *mtproto.AuthKeyInfo) *authKeyUtil {
	return &authKeyUtil{
		keyData: k,                                         // 初始化keyData
		key:     crypto.NewAuthKey(k.AuthKeyId, k.AuthKey), // 初始化key
	}
}

// Equal比较两个authKeyUtil实例是否相等
func (k *authKeyUtil) Equal(o *authKeyUtil) bool {
	return k.keyData.AuthKeyId == o.keyData.AuthKeyId
}

// AuthKeyId返回keyData中的AuthKeyId属性
func (k *authKeyUtil) AuthKeyId() int64 {
	return k.keyData.AuthKeyId
}

// AuthKeyType返回keyData中的AuthKeyType属性
func (k *authKeyUtil) AuthKeyType() int {
	return int(k.keyData.AuthKeyType)
}

// PermAuthKeyId返回keyData中的PermAuthKeyId属性
func (k *authKeyUtil) PermAuthKeyId() int64 {
	return k.keyData.PermAuthKeyId
}

// TempAuthKeyId返回keyData中的TempAuthKeyId属性
func (k *authKeyUtil) TempAuthKeyId() int64 {
	return k.keyData.TempAuthKeyId
}

// MediaTempAuthKeyId返回keyData中的MediaTempAuthKeyId属性
func (k *authKeyUtil) MediaTempAuthKeyId() int64 {
	return k.keyData.MediaTempAuthKeyId
}

// AesIgeEncrypt使用AES-IGE算法对原始数据进行加密
func (k *authKeyUtil) AesIgeEncrypt(rawData []byte) ([]byte, []byte, error) {
	return k.key.AesIgeEncrypt(rawData)
}

// AesIgeDecrypt使用AES-IGE算法对消息密钥和原始数据进行解密
func (k *authKeyUtil) AesIgeDecrypt(msgKey, rawData []byte) ([]byte, error) {
	return k.key.AesIgeDecrypt(msgKey, rawData)
}
