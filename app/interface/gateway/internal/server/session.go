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

package server

import (
	"errors"
	"os"
	"strings"

	"github.com/teamgram/teamgram-server/app/interface/gateway/internal/config"
	"github.com/teamgram/teamgram-server/app/interface/session/client"

	"github.com/zeromicro/go-zero/core/discov"
	"github.com/zeromicro/go-zero/core/hash"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/core/netx"
	"github.com/zeromicro/go-zero/core/stringx"
	"github.com/zeromicro/go-zero/zrpc"
)

const (
	allEths  = "0.0.0.0"
	envPodIp = "POD_IP"
)

var (
	ErrSessionNotFound = errors.New("not found session")
)

func figureOutListenOn(listenOn string) string {
	fields := strings.Split(listenOn, ":")
	if len(fields) == 0 {
		return listenOn
	}

	host := fields[0]
	if len(host) > 0 && host != allEths {
		return listenOn
	}

	ip := os.Getenv(envPodIp)
	if len(ip) == 0 {
		ip = netx.InternalIp()
	}
	if len(ip) == 0 {
		return listenOn
	}

	return strings.Join(append([]string{ip}, fields[1:]...), ":")
}

/*
*
dispatcher  *hash.ConsistentHash

这是一个一致性哈希实现的代码。一致性哈希是一种在分布式系统中用于负载均衡的技术，它将每个节点映射到一个哈希环上，
并将请求映射到该环上的某个节点来处理。这个代码实现了ConsistentHash结构体，其中包含了Add、AddWithReplicas、AddWithWeight、Get和Remove等方法。

其中，Add方法用于向哈希环中添加一个节点，默认情况下复制100个备份；AddWithReplicas方法用于向哈希环中添加一个节点，
并制定复制的备份数量；AddWithWeight方法用于向哈希环中添加一个节点，并指定权重，权重越高，所占比例就越大；Get方法用于查
找给定键在哈希环上对应的节点；Remove方法用于从哈希环中删除指定节点

以下是各个方法的注释：

NewConsistentHash
// NewConsistentHash返回一个一致性哈希对象。
func NewConsistentHash() *ConsistentHash {

NewCustomConsistentHash
// NewCustomConsistentHash返回一个具有给定复制数和哈希函数的一致性哈希对象。
func NewCustomConsistentHash(replicas int, fn Func) *ConsistentHash {

Add
// Add将节点添加到哈希环中，使用默认数量的备份。
// 后续的Add操作会覆盖前面的备份数量。
func (h *ConsistentHash) Add(node interface{}) {

AddWithReplicas
// AddWithReplicas将节点添加到哈希环中，
// 并指定要添加的副本数量。如果指定的副本数大于默认值，则设置为默认值。
// 后续的AddWithReplicas操作会覆盖先前的副本数量。
func (h *ConsistentHash) AddWithReplicas(node interface{}, replicas int) {

AddWithWeight
// AddWithWeight添加具有权重的节点。
// 权重是1到100之间的整数，表示百分比。
// 后续的AddWithWeight操作会覆盖先前的权重。
func (h *ConsistentHash) AddWithWeight(node interface{}, weight int) {

Get
// Get根据给定键返回哈希环上相应的节点。
func (h *ConsistentHash) Get(v interface{}) (interface{}, bool) {

Remove
// Remove从哈希环中删除给定的节点。
func (h *ConsistentHash) Remove(node interface{}) {
*/
type Session struct {
	gatewayId   string
	dispatcher  *hash.ConsistentHash
	errNotFound error
	sessions    map[string]session_client.SessionClient
}

func NewSession(c config.Config) *Session {
	sess := &Session{
		gatewayId:   figureOutListenOn(c.ListenOn),
		dispatcher:  hash.NewConsistentHash(),
		errNotFound: ErrSessionNotFound,
		sessions:    make(map[string]session_client.SessionClient),
	}
	sess.watch(c.Session)

	return sess
}

func (sess *Session) watch(c zrpc.RpcClientConf) {
	sub, _ := discov.NewSubscriber(c.Etcd.Hosts, c.Etcd.Key)
	update := func() {
		values := sub.Values()
		if len(values) == 0 {
			return
		}

		var (
			addClis    []session_client.SessionClient
			removeClis []session_client.SessionClient
		)

		sessions := map[string]session_client.SessionClient{}
		for _, v := range values {
			if old, ok := sess.sessions[v]; ok {
				sessions[v] = old
				continue
			}
			c.Endpoints = []string{v}
			cli, err := zrpc.NewClient(c)
			if err != nil {
				logx.Error("watchComet NewClient(%+v) error(%v)", values, err)
				return
			}
			sessionCli := session_client.NewSessionClient(cli)
			sessions[v] = sessionCli

			addClis = append(addClis, sessionCli)
		}

		for key, old := range sess.sessions {
			if !stringx.Contains(values, key) {
				removeClis = append(removeClis, old)
			}
		}

		for _, n := range addClis {
			sess.dispatcher.Add(n)
		}

		for _, n := range removeClis {
			sess.dispatcher.Remove(n)
		}

		sess.sessions = sessions
	}

	sub.AddListener(update)
	update()
}

func (sess *Session) getSessionClient(key string) (session_client.SessionClient, error) {
	val, ok := sess.dispatcher.Get(key)
	if !ok {
		return nil, ErrSessionNotFound
	}

	return val.(session_client.SessionClient), nil
}
