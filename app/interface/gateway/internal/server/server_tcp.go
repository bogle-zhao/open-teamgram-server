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
`github.com/teamgram/teamgram-server/app/interface/gateway/internal/server/server_tcp.go` 是 TeamGram 项目中的一个 TCP 服务器实现。该文件定义了 `ServerTCP` 结构体和其方法，用于接收并处理来自客户端的 TCP 连接请求。

具体来说，`ServerTCP` 中的 `Start` 方法会监听指定的地址 (`IP:port`)，并在新连接到来时调用 `handleConnection` 方法处理每个连接。`handleConnection` 方法解析收到的数据，并根据协议进行相应的处理，例如发送心跳包、响应客户端请求等。

此外，`ServerTCP` 还提供了一些辅助方法，如 `Send` 方法用于向客户端发送数据，`Broadcast` 方法用于广播数据给所有连接的客户端等。这些方法可以被业务逻辑层调用，完成与客户端的交互。

总之，`server_tcp.go` 实现了 TeamGram 项目中的 TCP 服务端部分，并提供了一些基本的数据传输和处理功能。
*/
package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/teamgram/marmota/pkg/hack"
	"github.com/teamgram/marmota/pkg/net2"
	"github.com/teamgram/marmota/pkg/timer2"
	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/interface/gateway/internal/server/codec"
	sessionpb "github.com/teamgram/teamgram-server/app/interface/session/session"

	"github.com/zeromicro/go-zero/core/logx"
)

type HandshakeStateCtx struct {
	State         int32  `json:"state,omitempty"`
	ResState      int32  `json:"res_state,omitempty"`
	Nonce         []byte `json:"nonce,omitempty"`
	ServerNonce   []byte `json:"server_nonce,omitempty"`
	NewNonce      []byte `json:"new_nonce,omitempty"`
	A             []byte `json:"a,omitempty"`
	P             []byte `json:"p,omitempty"`
	handshakeType int
	ExpiresIn     int32 `json:"expires_in,omitempty"`
}

func (m *HandshakeStateCtx) DebugString() string {
	s, _ := json.Marshal(m)
	return hack.String(s)
}

type connContext struct {
	// TODO(@benqi): lock
	sync.Mutex
	state           int // 是否握手阶段
	authKeys        []*authKeyUtil
	sessionId       int64
	isHttp          bool
	canSend         bool
	trd             *timer2.TimerData
	handshakes      []*HandshakeStateCtx
	clientIp        string
	xForwardedForIp string
}

func newConnContext() *connContext {
	return &connContext{
		state:           STATE_CONNECTED2,
		clientIp:        "",
		xForwardedForIp: "*",
	}
}

func (ctx *connContext) getClientIp(xForwarderForIp interface{}) string {
	ctx.Lock()
	defer ctx.Unlock()
	if ctx.xForwardedForIp == "*" {
		ctx.xForwardedForIp = ""
		if xForwarderForIp != nil {
			ctx.xForwardedForIp, _ = xForwarderForIp.(string)
		}
	}

	if ctx.xForwardedForIp != "" {
		return ctx.xForwardedForIp
	}
	return ctx.clientIp
}

func (ctx *connContext) setClientIp(ip string) {
	ctx.Lock()
	defer ctx.Unlock()

	ctx.clientIp = ip
}

func (ctx *connContext) getState() int {
	ctx.Lock()
	defer ctx.Unlock()
	return ctx.state
}

func (ctx *connContext) setState(state int) {
	ctx.Lock()
	defer ctx.Unlock()
	if ctx.state != state {
		ctx.state = state
	}
}

func (ctx *connContext) getAuthKey(id int64) *authKeyUtil {
	ctx.Lock()
	defer ctx.Unlock()
	for _, key := range ctx.authKeys {
		if key.AuthKeyId() == id {
			return key
		}
	}

	return nil
}

func (ctx *connContext) putAuthKey(k *authKeyUtil) {
	ctx.Lock()
	defer ctx.Unlock()
	for _, key := range ctx.authKeys {
		if key.Equal(k) {
			return
		}
	}

	ctx.authKeys = append(ctx.authKeys, k)
}

func (ctx *connContext) getAllAuthKeyId() (idList []int64) {
	ctx.Lock()
	defer ctx.Unlock()

	idList = make([]int64, len(ctx.authKeys))
	for i, key := range ctx.authKeys {
		idList[i] = key.AuthKeyId()
	}

	return
}

func (ctx *connContext) getHandshakeStateCtx(nonce []byte) *HandshakeStateCtx {
	ctx.Lock()
	defer ctx.Unlock()

	for _, state := range ctx.handshakes {
		if bytes.Equal(nonce, state.Nonce) {
			return state
		}
	}

	return nil
}

func (ctx *connContext) putHandshakeStateCt(state *HandshakeStateCtx) {
	ctx.Lock()
	defer ctx.Unlock()

	ctx.handshakes = append(ctx.handshakes, state)
}

func (ctx *connContext) encryptedMessageAble() bool {
	ctx.Lock()
	defer ctx.Unlock()
	//return ctx.state == STATE_CONNECTED2 ||
	//	ctx.state == STATE_AUTH_KEY ||
	//	(ctx.state == STATE_HANDSHAKE &&
	//		(ctx.handshakeCtx.State == STATE_pq_res ||
	//			(ctx.handshakeCtx.State == STATE_dh_gen_res &&
	//				ctx.handshakeCtx.ResState == RES_STATE_OK)))
	return true
}

func (ctx *connContext) DebugString() string {
	s := make([]string, 0, 4)
	s = append(s, fmt.Sprintf(`"state":%d`, ctx.state))
	// s = append(s, fmt.Sprintf(`"handshake_ctx":%s`, ctx.handshakeCtx.DebugString()))
	//if ctx.authKey != nil {
	//	s = append(s, fmt.Sprintf(`"auth_key_id":%d`, ctx.authKey.AuthKeyId()))
	//}
	return "{" + strings.Join(s, ",") + "}"
}

// TcpConnectionCallback 当有新连接建立时调用
// OnNewConnection
// /////////////////////////////////////////////////////////////////////////////////////////////
func (s *Server) OnNewConnection(conn *net2.TcpConnection) {
	ctx := newConnContext()
	ctx.setClientIp(strings.Split(conn.RemoteAddr().String(), ":")[0])

	logx.Infof("onNewConnection - {peer: %s, ctx: {%s}}", conn, ctx.DebugString())
	conn.Context = ctx
}

/**
这个函数是一个TCP连接数据到达时的回调函数，将收到的消息（msg）转换为MTPRawMessage类型。然后根据消息的AuthKeyId属性决定如何处理这条消息。

	如果AuthKeyId为0，则说明这是未加密的原始消息，此时会调用onUnencryptedMessage函数进行处理。

	如果AuthKeyId不为0，则说明这是加密的消息，需要使用正确的密钥进行解密。首先会检查ctx中是否存在对应的authKey，如果没有则从s中获取或者从sessionClient
	中查询获得，并将其存储到ctx中。然后调用onEncryptedMessage对消息进行解密和处理。

如果在处理过程中发生错误，则会记录日志、发送错误响应，并返回错误。
*/
// TcpConnectionCallback 当连接接收到数据时调用
func (s *Server) OnConnectionDataArrived(conn *net2.TcpConnection, msg interface{}) error {
	msg2, ok := msg.(*mtproto.MTPRawMessage)
	if !ok {
		err := fmt.Errorf("recv invalid MTPRawMessage: {peer: %s, msg: %v", conn, msg2)
		logx.Error(err.Error())
		return err
	}

	ctx, _ := conn.Context.(*connContext)

	logx.Infof("onConnectionDataArrived - receive data: {peer: %s, ctx: %s, msg: %s}", conn, ctx.DebugString(), msg2.DebugString())

	if msg2.ConnType() == codec.TRANSPORT_HTTP {
		ctx.isHttp = true
	}

	var err error
	// 未加密的消息
	if msg2.AuthKeyId() == 0 {
		//if ctx.getState() == STATE_AUTH_KEY {
		//	err = fmt.Errorf("invalid state STATE_AUTH_KEY: %d", ctx.getState())
		//	logx.Error("process msg error: {%v} - {peer: %s, ctx: %s, msg: %s}", err, conn, ctx.DebugString(), msg2.DebugString())
		//	conn.Close()
		//} else {
		//	err = s.onUnencryptedRawMessage(ctx, conn, msg2)
		//}
		err = s.onUnencryptedMessage(ctx, conn, msg2)
	} else {
		//if !ctx.encryptedMessageAble() {
		//	err = fmt.Errorf("invalid state: {state: %d, handshakeState: {%v}}", ctx.state, ctx.handshakeCtx)
		//	logx.Error("process msg error: {%v} - {peer: %s, ctx: %s, msg: %s}", err, conn, ctx.DebugString(), msg2.DebugString())
		//	conn.Close()
		//} else {
		//	if ctx.state != STATE_AUTH_KEY {
		authKey := ctx.getAuthKey(msg2.AuthKeyId())
		if authKey == nil {
			key := s.GetAuthKey(msg2.AuthKeyId())
			if key == nil {
				sessClient, err2 := s.session.getSessionClient(strconv.FormatInt(msg2.AuthKeyId(), 10))
				if err2 != nil {
					logx.Errorf("getSessionClient error: %v, {authKeyId: %d}", err2, msg2.AuthKeyId())
				} else {
					key, err2 = sessClient.SessionQueryAuthKey(context.Background(), &sessionpb.TLSessionQueryAuthKey{
						AuthKeyId: msg2.AuthKeyId(),
					})
					if err2 != nil {
						logx.Errorf("conn(%s) sessionQueryAuthKey error: %v", conn.String(), err2)
					}
				}
			}
			// key := s.GetAuthKey(msg2.AuthKeyId())
			if key == nil {
				err = fmt.Errorf("invalid auth_key_id: {%d}", msg2.AuthKeyId())
				logx.Error("invalid auth_key_id: {%v} - {peer: %s, ctx: %s, msg: %s}", err, conn, ctx.DebugString(), msg2.DebugString())
				var code = int32(-404)
				cData := make([]byte, 4)
				binary.LittleEndian.PutUint32(cData, uint32(code))
				conn.Send(&mtproto.MTPRawMessage{Payload: cData})
				// conn.Close()
				return err
			}
			authKey = newAuthKeyUtil(key)
			s.PutAuthKey(key)
			ctx.putAuthKey(authKey)
		}

		err = s.onEncryptedMessage(ctx, conn, authKey, msg2)
	}

	return err
}

// TcpConnectionCallback 当连接关闭时调用
func (s *Server) OnConnectionClosed(conn *net2.TcpConnection) {
	ctx, _ := conn.Context.(*connContext)
	logx.Info("onServerConnectionClosed - {peer:%s, ctx:%s}", conn, ctx.DebugString())

	if ctx.trd != nil {
		s.timer.Del(ctx.trd)
		ctx.trd = nil
	}

	sessId, connId := ctx.sessionId, conn.GetConnID()
	for _, id := range ctx.getAllAuthKeyId() {
		bDeleted := s.authSessionMgr.RemoveSession(id, sessId, connId)
		if bDeleted {
			s.sendToSessionClientClosed(id, ctx.sessionId, ctx.getClientIp(conn.Codec().Context()))
			logx.Infof("onServerConnectionClosed - sendClientClosed: {peer:%s, ctx:%s}", conn, ctx.DebugString())
		}
	}
}

// //////////////////////////////////////////////////////////////////////////////////////////////////
/**
这是一个 Go 语言编写的函数，它是一个 TCP 服务器的一部分。当该服务器接收到未加密的数据包时，将调用该函数对数据进行处理。下面是该函数的主要功能：

1. 检查数据长度是否小于 8，如果小于 8 则返回错误信息。
2. 解析从第 8 个字节开始的数据，并根据解析出来的对象类型执行相应的操作。支持的对象类型包括 TLReqPq, TLReqPqMulti, TLReq_DHParams,
	TLSetClient_DHParams 和 TLMsgsAck。
3. 对执行操作后得到的结果进行序列化，并发送给客户端。

具体而言，该函数实现了与 Telegram 的安全认证过程相关的功能。在接收到客户端发来的请求（如 TLReqPq 或 TLReq_DHParams）后，服务器会对请求进行解析，并根据请求内容生成相应的响应。
最后，服务器将响应序列化后发送给客户端。该过程会不断重复，直到客户端和服务器完成安全认证并建立起连接。
*/
func (s *Server) onUnencryptedMessage(ctx *connContext, conn *net2.TcpConnection, mmsg *mtproto.MTPRawMessage) error {
	logx.Info("receive unencryptedRawMessage: {peer: %s, ctx: %s, mmsg: %s}", conn, ctx.DebugString(), mmsg.DebugString())

	if len(mmsg.Payload) < 8 {
		err := fmt.Errorf("invalid data len < 8")
		logx.Error(err.Error())
		return err
	}

	_, obj, err := parseFromIncomingMessage(mmsg.Payload[8:])
	if err != nil {
		err := fmt.Errorf("invalid data len < 8")
		logx.Errorf(err.Error())
	}

	var rData []byte

	switch request := obj.(type) {
	case *mtproto.TLReqPq:
		logx.Infof("TLReqPq - {\"request\":%s", request.DebugString())
		resPQ, err := s.handshake.onReqPq(request)
		if err != nil {
			logx.Errorf("onHandshake error: {%v} - {peer: %s, ctx: %s, mmsg: %s}", err, conn, ctx.DebugString(), mmsg.DebugString())
			conn.Close()
			return err
		}
		ctx.putHandshakeStateCt(&HandshakeStateCtx{
			State:       STATE_pq_res,
			Nonce:       resPQ.GetNonce(),
			ServerNonce: resPQ.GetServerNonce(),
		})
		rData = serializeToBuffer(mtproto.GenerateMessageId(), resPQ)
	case *mtproto.TLReqPqMulti:
		logx.Infof("TLReqPqMulti - {\"request\":%s", request.DebugString())
		resPQ, err := s.handshake.onReqPqMulti(request)
		if err != nil {
			logx.Errorf("onHandshake error: {%v} - {peer: %s, ctx: %s, mmsg: %s}", err, conn, ctx.DebugString(), mmsg.DebugString())
			conn.Close()
			return err
		}
		ctx.putHandshakeStateCt(&HandshakeStateCtx{
			State:       STATE_pq_res,
			Nonce:       resPQ.GetNonce(),
			ServerNonce: resPQ.GetServerNonce(),
		})
		rData = serializeToBuffer(mtproto.GenerateMessageId(), resPQ)
	case *mtproto.TLReq_DHParams:
		logx.Infof("TLReq_DHParams - {\"request\":%s", request.DebugString())
		if state := ctx.getHandshakeStateCtx(request.Nonce); state != nil {
			resServerDHParam, err := s.handshake.onReqDHParams(state, obj.(*mtproto.TLReq_DHParams))
			if err != nil {
				logx.Errorf("onHandshake error: {%v} - {peer: %s, ctx: %s, mmsg: %s}", err, conn, ctx.DebugString(), mmsg.DebugString())
				conn.Close()
				return err
			}
			state.State = STATE_DH_params_res
			rData = serializeToBuffer(mtproto.GenerateMessageId(), resServerDHParam)
		} else {
			logx.Errorf("onHandshake error: {invalid nonce} - {peer: %s, ctx: %s, mmsg: %s}", conn, ctx.DebugString(), mmsg.DebugString())
			return conn.Close()
		}
	case *mtproto.TLSetClient_DHParams:
		logx.Infof("TLSetClient_DHParams - {\"request\":%s", request.DebugString())
		if state := ctx.getHandshakeStateCtx(request.Nonce); state != nil {
			resSetClientDHParamsAnswer, err := s.handshake.onSetClientDHParams(state, obj.(*mtproto.TLSetClient_DHParams))
			if err != nil {
				logx.Errorf("onHandshake error: {%v} - {peer: %s, ctx: %s, mmsg: %s}", err, conn, ctx.DebugString(), mmsg.DebugString())
				return conn.Close()
			}
			state.State = STATE_dh_gen_res
			rData = serializeToBuffer(mtproto.GenerateMessageId(), resSetClientDHParamsAnswer)
		} else {
			logx.Errorf("onHandshake error: {invalid nonce} - {peer: %s, ctx: %s, mmsg: %s}", conn, ctx.DebugString(), mmsg.DebugString())
			return conn.Close()
		}
	case *mtproto.TLMsgsAck:
		logx.Infof("TLMsgsAck - {\"request\":%s", request.DebugString())
		//err = s.onMsgsAck(state, obj.(*mtproto.TLMsgsAck))
		//return nil, err
		return nil
	default:
		err = fmt.Errorf("invalid handshake type")
		return conn.Close()
	}
	return conn.Send(&mtproto.MTPRawMessage{Payload: rData})
}

/*
*
这是一段用于对收到的加密消息进行处理的代码。在 Telegram 服务器接收到客户端的加密消息后会回调这个函数以进行解密和处理。下面是具体的代码分析：

1. 通过 authKey 对加密消息进行解密，获取解密后的消息内容。

2. 从解密后的消息中获取到 sessionId 和 authKeyId，其中 sessionId 是通过 Little Endian 编码方式存储在消息内容中的。

3. 根据 sessionId 的值判断这个会话是一个新会话还是一个已经存在的会话。

4. 获取到与 authKeyId 对应的会话客户端 sessClient。

5. 如果这是一个新会话，则根据 authKey、sessionId、连接 ID 等信息创建一个新的会话，并将消息发送到与客户端对应的服务端。

6. 如果这是一个已经存在的会话，则根据 authKey、sessionId、连接 ID 等信息将消息发送到与客户端对应的服务端。

7. 处理完毕后返回 nil，表示处理成功。
*/
func (s *Server) onEncryptedMessage(ctx *connContext, conn *net2.TcpConnection, authKey *authKeyUtil, mmsg *mtproto.MTPRawMessage) error {
	mtpRwaData, err := authKey.AesIgeDecrypt(mmsg.Payload[8:8+16], mmsg.Payload[24:])
	if err != nil {
		logx.Errorf("conn(%s) decrypt error: {%v}", conn.String(), err)
		return err
	}

	var (
		sessionId = int64(binary.LittleEndian.Uint64(mtpRwaData[8:]))
		isNew     = ctx.sessionId == 0
		authKeyId = mmsg.AuthKeyId()
	)
	if isNew {
		ctx.sessionId = sessionId
	} else {
		// check sessionId??
	}

	sessClient, err2 := s.session.getSessionClient(strconv.FormatInt(mmsg.AuthKeyId(), 10))
	if err2 != nil {
		logx.Errorf("conn(%s) getSessionClient error: %v, {authKeyId: %d}", conn.String(), err, mmsg.AuthKeyId())
		return err2
	}

	if isNew {
		if s.authSessionMgr.AddNewSession(authKey, sessionId, conn.GetConnID()) {
			sessClient.SessionCreateSession(context.Background(),
				&sessionpb.TLSessionCreateSession{
					Client: sessionpb.MakeTLSessionClientEvent(&sessionpb.SessionClientEvent{
						ServerId:  s.session.gatewayId,
						AuthKeyId: authKeyId,
						SessionId: sessionId,
						ClientIp:  ctx.getClientIp(conn.Codec().Context()),
					}).To_SessionClientEvent(),
				})
		}
	}

	_, _ = sessClient.SessionSendDataToSession(context.Background(), &sessionpb.TLSessionSendDataToSession{
		Data: &sessionpb.SessionClientData{
			ServerId:  s.session.gatewayId,
			AuthKeyId: authKey.AuthKeyId(),
			SessionId: sessionId,
			Salt:      int64(binary.LittleEndian.Uint64(mtpRwaData)),
			Payload:   mtpRwaData[16:],
			ClientIp:  ctx.getClientIp(conn.Codec().Context()),
		},
	})

	return nil
}

func (s *Server) GetConnByConnID(id uint64) *net2.TcpConnection {
	return s.server.GetConnection(id)
}

func (s *Server) SendToClient(conn *net2.TcpConnection, authKey *authKeyUtil, b []byte) error {
	ctx, _ := conn.Context.(*connContext)
	if ctx.trd != nil {
		logx.Info("del conn timeout")
		s.timer.Del(ctx.trd)
		ctx.trd = nil
	}

	msgKey, mtpRawData, _ := authKey.AesIgeEncrypt(b)
	x := mtproto.NewEncodeBuf(8 + len(msgKey) + len(mtpRawData))
	x.Long(authKey.AuthKeyId())
	x.Bytes(msgKey)
	x.Bytes(mtpRawData)
	//logx.Info("egate receiveData - ready sendToClient to: {peer: %s, auth_key_id = %d, session_id = %d}",
	//	conn,
	//	r.AuthKeyId,
	//	r.SessionId)

	msg := &mtproto.MTPRawMessage{Payload: x.GetBuf()}
	if ctx.isHttp {
		//if !ctx.canSend {
		//	s.authSessionMgr.PushBackHttpData(authKey.AuthKeyId(), ctx.sessionId, msg)
		//	return nil
		//}
		ctx.canSend = false
	}

	// err := conn.Send(&mtproto.MTPRawMessage{Payload: x.GetBuf()})
	err := conn.Send(msg)
	if err != nil {
		logx.Errorf("send error: %v", err)
		return err
	}

	return nil
}

func (s *Server) sendToSessionClientNew(authKeyId, sessionId int64, clientIp string) {
	c, err := s.session.getSessionClient(strconv.FormatInt(authKeyId, 10))
	if err != nil {
		logx.Errorf("getSessionClient error: {%v} - {authKeyId: %d}", err, authKeyId)
		return
	}

	c.SessionCreateSession(context.Background(), &sessionpb.TLSessionCreateSession{
		Client: &sessionpb.SessionClientEvent{
			ServerId:  s.session.gatewayId,
			AuthKeyId: authKeyId,
			SessionId: sessionId,
			ClientIp:  clientIp,
		},
	})
}

func (s *Server) sendToSessionClientClosed(authKeyId, sessionId int64, clientIp string) {
	c, err := s.session.getSessionClient(strconv.FormatInt(authKeyId, 10))
	if err != nil {
		logx.Errorf("getSessionClient error: {%v} - {authKeyId: %d}", err, authKeyId)
		return
	}

	c.SessionCloseSession(context.Background(), &sessionpb.TLSessionCloseSession{
		Client: &sessionpb.SessionClientEvent{
			ServerId:  s.session.gatewayId,
			AuthKeyId: authKeyId,
			SessionId: sessionId,
			ClientIp:  clientIp,
		},
	})
}
