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
	allEths  = "0.0.0.0" // 列出所有网口的 IP 地址
	envPodIp = "POD_IP"  // Pod 的 IP 地址
)

var (
	ErrSessionNotFound = errors.New("not found session") // 当会话找不到时返回的错误信息
)

// figureOutListenOn 根据配置文件中的监听地址来确定该服务器应该监听哪个 IP 地址。
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

// Session 存储了网关服务器 ID、一致性哈希表以分发会话到不同的服务器、当找不到会话时的错误信息以及当前活动会话的映射。
type Session struct {
	gatewayId   string                                     // 网关服务器 ID
	dispatcher  *hash.ConsistentHash                       // 一致性哈希表
	errNotFound error                                      // 当会话找不到时返回的错误信息
	sessions    map[string]session_client.SessionClient    // 当前活动会话的映射
}

// NewSession 使用服务器配置文件中的信息初始化一个新的 Session 实例。
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

// watch 使用 discov 包订阅 etcd 的更新，并根据检测到的更改添加或删除会话客户端。
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
			if old, ok := sess.sessions[v]; ok { // 如果已存在，则直接保存在新 sessions 映射中
				sessions[v] = old
				continue
			}
			c.Endpoints = []string{v}                   // 连接会话客户端
			cli, err := zrpc.NewClient(c)
			if err != nil {
				logx.Error("watchComet NewClient(%+v) error(%v)", values, err)
				return
			}
			sessionCli := session_client.NewSessionClient(cli)
			sessions[v] = sessionCli                   // 将新的会话客户端加入新映射
			addClis = append(addClis, sessionCli)      // 添加到要添加的切片中
		}

		for key, old := range sess.sessions {
			if !stringx.Contains(values, key) {
				removeClis = append(removeClis, old)  // 添加到要删除的切片中
			}
		}

		for _, n := range addClis {                  // 向 dispatcher 添加要添加的会话客户端
			sess.dispatcher.Add(n)

