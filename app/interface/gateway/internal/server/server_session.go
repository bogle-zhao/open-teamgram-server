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
	"context"
	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/interface/gateway/gateway"

	"github.com/zeromicro/go-zero/core/logx"
)

/*
   bool error = false;
   if (length <= 24 + 32) {
       int32_t code = data->readInt32(&error);
       if (code == 0) {
           if (LOGS_ENABLED) DEBUG_D("mtproto noop");
       } else if (code == -1) {
           int32_t ackId = data->readInt32(&error);
           if (!error) {
               onConnectionQuickAckReceived(connection, ackId & (~(1 << 31)));
           }
       } else {
           Datacenter *datacenter = connection->getDatacenter();
           if (LOGS_ENABLED) DEBUG_W("mtproto error = %d", code);
           if (code == -444 && connection->getConnectionType() == ConnectionTypeGeneric && !proxyAddress.empty() && !proxySecret.empty()) {
               if (delegate != nullptr) {
                   delegate->onProxyError(instanceNum);
               }
           } else if (code == -404 && (datacenter->isCdnDatacenter || PFS_ENABLED)) {
               if (!datacenter->isHandshaking(connection->isMediaConnection)) {
                   datacenter->clearAuthKey(connection->isMediaConnection ? HandshakeTypeMediaTemp : HandshakeTypeTemp);
                   datacenter->beginHandshake(connection->isMediaConnection ? HandshakeTypeMediaTemp : HandshakeTypeTemp, true);
                   if (LOGS_ENABLED) DEBUG_D("connection(%p, account%u, dc%u, type %d) reset auth key due to -404 error", connection, instanceNum, datacenter->getDatacenterId(), connection->getConnectionType());
               }
           } else {
               connection->reconnect();
           }
       }
       return;
   }
*/

/**
该代码定义了一个Server结构体，其中包含了一个GatewaySendDataToGateway的方法。这个方法接受一个context
和一个gateway.TLGatewaySendDataToGateway类型的参数，返回一个mtproto.Bool和一个error类型的返回值。在这个方法中，
首先打印了一条日志记录，并声明了一个authKey变量。

然后通过调用s.authSessionMgr.FoundSessionConnIdList(in.AuthKeyId, in.SessionId)方法获取到connIdList（连接ID列表）
以及authKey对象，如果connIdList为nil，则会打印一个错误日志并且返回一个BoolFalse值。之后对于每一个connId，在发送数据之前都进行了一些校验，
比如是否可以发送数据等，然后调用了s.SendToClient方法将数据发送给客户端。如果发送成功则会打印结果并返回True，否则会打印错误信息并返回True。
*/
// GatewaySendDataToGateway
// gateway.sendDataToGateway auth_key_id:long session_id:long payload:bytes = Bool;
func (s *Server) GatewaySendDataToGateway(ctx context.Context, in *gateway.TLGatewaySendDataToGateway) (reply *mtproto.Bool, err error) {
	logx.Infof("ReceiveData - request: {kId: %d, sessionId: %d, payloadLen: %d}", in.AuthKeyId, in.SessionId, len(in.Payload))

	var (
		authKey *authKeyUtil
	)

	// TODO(@benqi): 并发问题
	authKey, connIdList := s.authSessionMgr.FoundSessionConnIdList(in.AuthKeyId, in.SessionId)
	if connIdList == nil {
		logx.Errorf("ReceiveData - not found connIdList - keyId: %d, sessionId: %d", in.AuthKeyId, in.SessionId)
		return mtproto.BoolFalse, nil
	}

	//msgKey, mtpRawData, _ := authKey.AesIgeEncrypt(in.Payload)
	//x := mtproto.NewEncodeBuf(8 + len(msgKey) + len(mtpRawData))
	//x.Long(authKey.AuthKeyId())
	//x.Bytes(msgKey)
	//x.Bytes(mtpRawData)
	//msg := &mtproto.MTPRawMessage{Payload: x.GetBuf()}

	//for _, connId := range connIdList {
	//	s.svr.Trigger(connId, func(c gnet.Conn) {
	//		if err := c.UnThreadSafeWrite(msg); err != nil {
	//			logx.Errorf("sendToClient error: %v", err)
	//		}
	//	})
	//}

	for _, connId := range connIdList {
		logx.Infof("[keyId: %d, sessionId: %d]: %v", in.AuthKeyId, in.SessionId, connId)
		conn2 := s.server.GetConnection(connId)
		if conn2 != nil {
			ctx, _ := conn2.Context.(*connContext)
			authKey = ctx.getAuthKey(in.AuthKeyId)
			if authKey == nil {
				logx.Errorf("invalid authKeyId, authKeyId = %d", in.AuthKeyId)
				continue
			}
			if ctx.isHttp {
				// isHttp = true
				if !ctx.canSend {
					continue
				}
			}
			// conn = conn2
			// break
			if err = s.SendToClient(conn2, authKey, in.Payload); err == nil {
				logx.Infof("ReceiveData -  result: {auth_key_id = %d, session_id = %d, conn = %s}",
					in.AuthKeyId,
					in.SessionId,
					conn2)

				if ctx.isHttp {
					s.authSessionMgr.PushBackHttpData(in.AuthKeyId, in.SessionId, in.Payload)
				}
				return mtproto.ToBool(true), nil
			} else {
				logx.Errorf("ReceiveData - sendToClient error (%v), auth_key_id = %d, session_id = %d, conn_id_list = %v",
					err,
					in.AuthKeyId,
					in.SessionId,
					connIdList)
			}
		}
	}

	return mtproto.BoolTrue, nil
}
