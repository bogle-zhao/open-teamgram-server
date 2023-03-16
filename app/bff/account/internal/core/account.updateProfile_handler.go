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

package core

import (
	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/messenger/sync/sync"
	userpb "github.com/teamgram/teamgram-server/app/service/biz/user/user"
)

/**
这段代码是一个 Telegram 服务端的 Go 语言实现中的 AccountCore 结构体的 AccountUpdateProfile 方法。该方法用于更新用户的个人资料信息，
如用户的名称、姓氏和个人描述等。

其中，通过调用 c.svcCtx.Dao.UserClient.UserGetImmutableUser 方法获取当前用户的不可变信息，并根据传入的参数进行更新。
如果传入的参数中包含 about（个人描述）字段，它会检查其长度是否小于等于70个字符，并且允许为空。如果符合要求，就会将该字段更新到数据库中。

如果传入的参数没有 about 字段，则会检查 first_name（名字）字段是否存在并且非空。如果 first_name 存在并且发生了改变，
以及 last_name（姓氏）字段也有变化，就会将新的名字和姓氏更新到数据库中，并且使用 SyncUpdatesNotMe 方法通知其他相关用户有关此更改的更新。

最后，方法返回更新后的用户信息。
*/
// AccountUpdateProfile
// account.updateProfile#78515775 flags:# first_name:flags.0?string last_name:flags.1?string about:flags.2?string = User;
func (c *AccountCore) AccountUpdateProfile(in *mtproto.TLAccountUpdateProfile) (*mtproto.User, error) {
	me, err := c.svcCtx.Dao.UserClient.UserGetImmutableUser(c.ctx, &userpb.TLUserGetImmutableUser{
		Id: c.MD.UserId,
	})

	if in.GetAbout() != nil {
		//// about长度<70并且可以为emtpy
		if len(in.GetAbout().GetValue()) > 70 {
			err = mtproto.ErrAboutTooLong
			c.Logger.Errorf("account.updateProfile - error: %v", err)
			return nil, err
		}

		if in.GetAbout().GetValue() != me.About() {
			if _, err = c.svcCtx.Dao.UserClient.UserUpdateAbout(c.ctx, &userpb.TLUserUpdateAbout{
				UserId: c.MD.UserId,
				About:  in.GetAbout().GetValue(),
			}); err != nil {
				c.Logger.Errorf("account.updateProfile - error: %v", err)
			} else {
				me.SetAbout(in.GetAbout().GetValue())
			}
		}
	} else {
		if in.GetFirstName().GetValue() == "" {
			err = mtproto.ErrFirstNameInvalid
			c.Logger.Errorf("account.updateProfile - error: bad request (%v)", err)
			return nil, err
		}

		if in.GetFirstName().GetValue() != me.FirstName() ||
			in.GetLastName().GetValue() != me.LastName() {
			if _, err = c.svcCtx.Dao.UserClient.UserUpdateFirstAndLastName(c.ctx, &userpb.TLUserUpdateFirstAndLastName{
				UserId:    c.MD.UserId,
				FirstName: in.GetFirstName().GetValue(),
				LastName:  in.GetLastName().GetValue(),
			}); err != nil {
				c.Logger.Errorf("account.updateProfile - error: %v", err)
			} else {
				me.SetFirstName(in.GetFirstName().GetValue())
				me.SetLastName(in.GetLastName().GetValue())
			}

			c.svcCtx.Dao.SyncClient.SyncUpdatesNotMe(c.ctx, &sync.TLSyncUpdatesNotMe{
				UserId:    c.MD.UserId,
				AuthKeyId: c.MD.AuthId,
				Updates: mtproto.MakeUpdatesByUpdates(mtproto.MakeTLUpdateUserName(&mtproto.Update{
					UserId:    c.MD.UserId,
					FirstName: in.GetFirstName().GetValue(),
					LastName:  in.GetLastName().GetValue(),
					Username:  me.Username(),
				}).To_Update()),
			})
		}
	}

	return me.ToSelfUser(), nil
}
