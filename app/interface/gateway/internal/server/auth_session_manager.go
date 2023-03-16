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
这段代码定义了一个名为 authSessionManager 的结构体，用于管理会话。具体功能如下：

1. 定义 sessionData 结构体，包含 sessionId、connIdList 和 pendingHttpDataList 等字段。
2. 定义 authSession 结构体，包含 authKey 和 sessionList 字段，其中 sessionList 以 sessionId 为键值存储 sessionData 实例。
3. 定义 authSessionManager 结构体，包含 rw、sessions 字段，其中 sessions 以 authKeyId 为键值存储 authSession 实例。
4. NewAuthSessionManager 方法用于创建 authSessionManager 实例。
5. PushBackHttpData 方法向指定会话的 pendingHttpDataList 中添加数据。
6. PopFrontHttpData 方法从指定会话的 pendingHttpDataList 中取出第一条数据并返回。
7. AddNewSession 方法用于向 authSessionManager 中添加新的会话，并将该会话与相应的 authKey 关联，同时将 connId 存储在对应的 sessionData 实例中。
8. RemoveSession 方法用于删除指定会话及其所有关联的 connId。
9. FoundSessionConnIdList 方法用于获取指定会话的所有 connId。

总体来说，这段代码实现了会话的管理功能，包括添加、删除、查询等操作，并且可以通过 PushBackHttpData 和 PopFrontHttpData 方法在会话中存储和获取数据。
*/

package server

import (
	"container/list"
	"sync"

	"github.com/zeromicro/go-zero/core/logx"
)

type sessionData struct {
	sessionId           int64
	connIdList          *list.List
	pendingHttpDataList *list.List
}

type authSession struct {
	authKey     *authKeyUtil
	sessionList map[int64]sessionData
}

type authSessionManager struct {
	rw       sync.RWMutex
	sessions map[int64]*authSession
}

func NewAuthSessionManager() *authSessionManager {
	return &authSessionManager{
		sessions: make(map[int64]*authSession),
	}
}

/*
*
这段代码实现了一个认证会话管理（authSessionManager），主要包含以下方法：

PushBackHttpData：将接收到的 HTTP 数据添加到指定认证会话中，待客户端连接后再发送给客户端。
PopFrontHttpData：从指定认证会话中取出最早未发送给客户端的 HTTP 数据，并从队列中删除。
AddNewSession：添加一个新的认证会话，包括会话 ID、连接 ID 以及认证 Key 的信息。
RemoveSession：删除指定认证会话中的指定连接，若该会话不再包含任何连接，则将其从认证会话管理器中删除。
FoundSessionConnIdList：查询指定认证会话中所有连接的连接 ID 列表。
其中，认证会话（authSession）是按照认证 Key 分类的，每个认证 Key 下面可以有多个会话，每个会话有唯一的会话 ID 和多个连接。每个连接有自己的连接 ID。

除此之外，还定义了 sessionData 结构体，用于存储会话信息和对应连接的状态；authSession 结构体，用于存储某个认证 Key 下所有的会话；authSessionManager 结构体，用于管理所有的认证会话。同时，使用了 container/list 包来实现基于链表的数据结构。
*/

/*
*
这是认证会话管理器的一个方法，名为 PushBackHttpData。该方法用于将接收到的 HTTP 数据添加到指定的认证会话中，待客户端连接后再发送给客户端。

具体功能如下：

获取读写锁的写锁，以保证在并发环境下访问 sessions 安全。
根据认证 Key 和会话 ID 查找对应的 authSession 和 sessionData 对象。
将接收到的 HTTP 数据（字节数组）添加到 sessionData 对象中 pendingHttpDataList 队列的头部。
释放读写锁的写锁。
需要注意的是，pendingHttpDataList 队列是基于 container/list 包实现的双向链表，因此通过调用 PushFront 方法将数据添加到头部。
*/
func (m *authSessionManager) PushBackHttpData(authKeyId, sessionId int64, raw []byte) {
	m.rw.Lock()
	defer m.rw.Unlock()

	if v, ok := m.sessions[authKeyId]; ok {
		if v2, ok2 := v.sessionList[sessionId]; ok2 {
			v2.pendingHttpDataList.PushFront(raw)
		}
	}
}

func (m *authSessionManager) PopFrontHttpData(authKeyId, sessionId int64) []byte {
	m.rw.Lock()
	defer m.rw.Unlock()

	if v, ok := m.sessions[authKeyId]; ok {
		if v2, ok2 := v.sessionList[sessionId]; ok2 {
			if e := v2.pendingHttpDataList.Front(); e != nil {
				v2.pendingHttpDataList.Remove(e)
				return e.Value.([]byte)
			}
		}
	}
	return nil
}

func (m *authSessionManager) AddNewSession(authKey *authKeyUtil, sessionId int64, connId uint64) (bNew bool) {
	logx.Infof("addNewSession: auth_key_id: %d, session_id: %d, conn_id: %d",
		authKey.AuthKeyId(),
		sessionId,
		connId)

	m.rw.Lock()
	defer m.rw.Unlock()

	if v, ok := m.sessions[authKey.AuthKeyId()]; ok {
		var (
			// sIdx     = -1
			cExisted = false
		)
		if v2, ok2 := v.sessionList[sessionId]; ok2 {
			for e := v2.connIdList.Front(); e != nil; e = e.Next() {
				if e.Value.(uint64) == connId {
					cExisted = true
					break
				}
			}
			if !cExisted {
				v2.connIdList.PushBack(connId)
			}
		} else {
			s := sessionData{
				sessionId:           sessionId,
				connIdList:          list.New(),
				pendingHttpDataList: list.New(),
			}
			s.connIdList.PushBack(connId)
			v.sessionList[sessionId] = s
			bNew = true
		}
	} else {
		s := sessionData{
			sessionId:           sessionId,
			connIdList:          list.New(),
			pendingHttpDataList: list.New(),
		}
		s.connIdList.PushBack(connId)

		m.sessions[authKey.AuthKeyId()] = &authSession{
			authKey: authKey,
			sessionList: map[int64]sessionData{
				sessionId: s,
			},
		}
		bNew = true
	}
	return
}

func (m *authSessionManager) RemoveSession(authKeyId, sessionId int64, connId uint64) (bDeleted bool) {
	logx.Infof("removeSession: auth_key_id: %d, session_id: %d, conn_id: %d",
		authKeyId,
		sessionId,
		connId)

	m.rw.Lock()
	defer m.rw.Unlock()

	if v, ok := m.sessions[authKeyId]; ok {
		if v2, ok2 := v.sessionList[sessionId]; ok2 {
			for e := v2.connIdList.Front(); e != nil; e = e.Next() {
				if e.Value.(uint64) == connId {
					v2.connIdList.Remove(e)
					break
				}
			}
			if v2.connIdList.Len() == 0 {
				delete(v.sessionList, sessionId)
				bDeleted = true
			}
			if len(v.sessionList) == 0 {
				delete(m.sessions, authKeyId)
			}
		}
	}

	return
}

func (m *authSessionManager) FoundSessionConnIdList(authKeyId, sessionId int64) (*authKeyUtil, []uint64) {
	m.rw.RLock()
	defer m.rw.RUnlock()

	if v, ok := m.sessions[authKeyId]; ok {
		if v2, ok2 := v.sessionList[sessionId]; ok2 {
			connIdList := make([]uint64, 0, v2.connIdList.Len())
			for e := v2.connIdList.Back(); e != nil; e = e.Prev() {
				connIdList = append(connIdList, e.Value.(uint64))
			}
			return v.authKey, connIdList
		}
	}

	return nil, nil
}
