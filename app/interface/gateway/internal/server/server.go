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
根据您提供的路径，我看到这是TeamGram服务器应用程序中的一个内部网关接口模块。这个模块可能包含以下一些功能和使用：

网关路由器：该模块可能包含一个网关路由器，用于将传入请求发送到正确的处理程序或服务。路由器可以基于请求方法、请求路径或其他标准来确定如何处理请求。

请求处理程序：该模块还可能包含一些请求处理程序，用于处理特定类型的请求。例如，处理身份验证请求的处理程序可能与处理数据查询请求的处理程序有所不同。

中间件：该模块可能会包含一些中间件，用于对传入请求进行预处理或后处理。例如，中间件可以在请求到达处理程序之前验证身份验证令牌。

与其他模块通信：该模块可能需要与其他模块进行通信，以获取所需的数据或执行必要的操作。为此，它可能会使用某种形式的客户端库或API。

总体而言，这个模块的目的是作为TeamGram服务器应用程序的内部网关接口，帮助处理传入请求并将它们分发到正确的处理程序或服务。
*/
package server

import (
	"context"
	"fmt"
	"github.com/teamgram/marmota/pkg/net2"
	"github.com/teamgram/marmota/pkg/timer2"
	"github.com/teamgram/proto/mtproto"
	sessionpb "github.com/teamgram/teamgram-server/app/interface/session/session"
	"github.com/zeromicro/go-zero/core/logx"
	"strconv"

	"github.com/teamgram/marmota/pkg/cache"
	"github.com/teamgram/teamgram-server/app/interface/gateway/internal/config"
)

var (
	//etcdPrefix is a etcd globe key prefix
	endpoints string
)

type Server struct {
	c      *config.Config
	server *net2.TcpServer2
	// pool           *goroutine.Pool
	cache          *cache.LRUCache
	handshake      *handshake
	session        *Session
	authSessionMgr *authSessionManager
	timer          *timer2.Timer // 32 * 2048
}

/*
*
创建一个名为Server的实例，其中包含了一些属性和方法。具体功能如下：

1. 通过传入的config.Config类型c初始化Server实例s的各个属性。

2. 将c.KeyFingerprint转换为64位无符号整型keyFingerprint，并根据c.KeyFile和keyFingerprint创建handshake对象并将其赋值给Server实例s的handshake属性。

3. 如果在以上过程中出现了错误，则程序会panic抛出异常。

4. 使用cache.NewLRUCache函数创建一个容量为10MB的LRUCache，并将其赋值给Server实例s的cache属性。

5. 调用NewSession函数，创建一个Session实例并将其赋值给Server实例s的session属性。

6. 将c指针赋值给Server实例s的c属性。

7. 返回Server实例s。
*/
func New(c config.Config) *Server {
	var (
		err error
		s   = new(Server)
	)

	// 创建一个名为s的Server实例，并初始化其各个属性
	s.timer = timer2.NewTimer(1024)            // 初始化timer属性
	s.authSessionMgr = NewAuthSessionManager() // 初始化authSessionMgr属性

	// 将c.KeyFingerprint转换为64位无符号整型keyFingerprint，并根据c.KeyFile和keyFingerprint创建handshake对象并将其赋值给Server实例s的handshake属性
	keyFingerprint, err := strconv.ParseUint(c.KeyFingerprint, 10, 64)
	if err != nil {
		panic(err) // 如果转换过程出现错误，程序抛出异常
	}
	s.handshake, err = newHandshake(c.KeyFile, keyFingerprint,
		func(ctx context.Context, key *mtproto.AuthKeyInfo, salt *mtproto.FutureSalt, expiresIn int32) error {
			// 根据key.AuthKeyId从session中获取对应的客户端连接sessClient
			sessClient, err2 := s.session.getSessionClient(strconv.FormatInt(key.AuthKeyId, 10))
			if err2 != nil {
				logx.Errorf("getSessionClient error: %v, {authKeyId: %d}", err, key.AuthKeyId)
				return err2
			}

			// 调用sessClient的SessionSetAuthKey方法，设置认证密钥信息
			var (
				rB *mtproto.Bool
			)
			rB, err2 = sessClient.SessionSetAuthKey(context.Background(), &sessionpb.TLSessionSetAuthKey{
				AuthKey:    key,
				FutureSalt: salt,
				ExpiresIn:  expiresIn,
			})
			// 如果调用过程出现错误，则记录日志并返回err2
			if err2 != nil {
				logx.Errorf("saveAuthKeyInfo not successful - auth_key_id:%d, err:%v", key.AuthKeyId, err2)
				return err2
			} else if !mtproto.FromBool(rB) {
				logx.Errorf("saveAuthKeyInfo not successful - auth_key_id:%d", key.AuthKeyId)
				err2 = fmt.Errorf("saveAuthKeyInfo error")
				return err2
			} else {
				// 将key对应的认证密钥信息加入到authKeys中
				s.PutAuthKey(&mtproto.AuthKeyInfo{
					AuthKeyId:          key.AuthKeyId,
					AuthKey:            key.AuthKey,
					AuthKeyType:        key.AuthKeyType,
					PermAuthKeyId:      key.PermAuthKeyId,
					TempAuthKeyId:      key.TempAuthKeyId,
					MediaTempAuthKeyId: key.MediaTempAuthKeyId})
			}
			return nil
		})

	// 如果在以上过程中出现了错误，则程序会panic抛出异常。
	if err != nil {
		panic(err)
	}

	// 使用cache.NewLRUCache函数创建一个容量为10MB的LRUCache，并将其赋值给Server实例s的cache属性。
	// 最近最少使用的缓存
	s.cache = cache.NewLRUCache(10 * 1024 * 1024) // cache capacity: 10MB

	// 调用NewSession函数，创建一个Session实例并将其赋值给Server实例s的session属性。
	s.session = NewSession(c)

	// 将指向c的指针赋值给Server实例s的c属性。
	s.c = &c

	// 返回Server实例s。
	return s
}

func (s *Server) Close() {
	s.server.Stop()
}

// Ping ping the resource.
func (s *Server) Ping(ctx context.Context) (err error) {
	return nil
}

func (s *Server) Serve() error {
	serv, err := net2.NewTcpServer2(s.c.Server, s.c.MaxProc, s)
	if err != nil {
		panic(err)
	}
	s.server = serv
	s.server.Serve()

	return nil
}
