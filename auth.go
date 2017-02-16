/*
 * Copyright 2017 Manuel Gauto (github.com/twa16)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/


package simpleauth

import (
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
	"github.com/satori/go.uuid"
	"strings"
	"time"
)

type AuthProvider struct {
	Database *gorm.DB
	SessionExpireTimeSeconds int64
}

type AuthUser struct {
	gorm.Model
	Username string
	PasswordHash []byte
	FirstName string
	LastName string
	Email string
	PhoneNumber string
	Role string
	Permissions []AuthPermission
	UserMetaData []AuthUserMetadata
	Sessions     []AuthSession
}

type AuthPermission struct {
	gorm.Model
	AuthUserID uint
	Permission string
}

type AuthUserMetadata struct {
	gorm.Model
	AuthUserID uint
	Key string
	Value string
}

type AuthSession struct {
	gorm.Model
	AuthenticationToken string //Session key used to authorize requests
	AuthUserID              uint   //ID of user that this token belongs to
	LastSeen            int64  //Linux time of last API Call
	Persistent	    bool   //If this is set to true, the key never expires.
}

type AuthSessionCheckResponse struct {
	AuthSession *AuthSession
	IsExpired bool
}

func (authProvider AuthProvider) CreateUser(user AuthUser) (AuthUser, error) {
	err := authProvider.Database.Create(&user).Error
	return user, err
}

func (authProvider AuthProvider) GetUser(username string) (AuthUser, error) {
	var user AuthUser
	err := authProvider.Database.Where("username = ?", username).First(&user).Error
	if err != nil {
		return user, err
	}
	user, err = authProvider.GetUserByID(user.ID)
	return user, err
}

func (authProvider AuthProvider) GetUserByID(userID uint) (AuthUser, error) {
	var user AuthUser
	err := authProvider.Database.First(&user, userID).Error
	authProvider.Database.Model(&user).Related(&user.UserMetaData)
	authProvider.Database.Model(&user).Related(&user.Permissions)
	authProvider.Database.Model(&user).Related(&user.Sessions)
	return user, err
}

//CheckLogin This function returns the user true if the credentials correspond to a user
func (authProvider AuthProvider) CheckLogin(username string, password string) (bool, error) {
	userObject, err := authProvider.GetUser(username)
	//Check if there is an error
	if err != nil {
		return false, err
	}
	//Check if the user exists
	if userObject.Username == "" {
		return false, nil
	}
	compareResultError := bcrypt.CompareHashAndPassword(userObject.PasswordHash, []byte(password))
	return compareResultError == nil, nil
}

//GenerateSessionKey Generates a AuthSession for a user. If 'persistent' is set to true the session will never expire.
func (authProvider AuthProvider) GenerateSessionKey(userID uint, persistent bool) (AuthSession, error) {
	sessionKey := AuthSession{}
	sessionKey.AuthUserID = userID
	sessionKey.Persistent = persistent
	sessionKey.AuthenticationToken = uuid.NewV4().String()
	err := authProvider.Database.Create(&sessionKey).Error
	return sessionKey, err
}

//CheckSessionKey Checks a session key and returns the session if it exists
func (authProvider AuthProvider) CheckSessionKey(sessionKey string) (AuthSessionCheckResponse, error) {
	var session AuthSession
	err := authProvider.Database.Where("authentication_token = ?", sessionKey).First(&session).Error

	curTime := time.Now().Unix()
	checkResponse := AuthSessionCheckResponse{}
	checkResponse.AuthSession = &session
	checkResponse.IsExpired = (curTime - session.LastSeen) < authProvider.SessionExpireTimeSeconds
	return checkResponse, err
}

func (authProvider AuthProvider) UpdateSessionAccessTime(session AuthSession) {
	curTime := time.Now().Unix()
	if (curTime - session.LastSeen) < authProvider.SessionExpireTimeSeconds {
		session.LastSeen = curTime
		authProvider.Database.Save(&session)
	}
}

//CheckPermission Returns true if the user has the provided permission
func (authProvider AuthProvider) CheckPermission(userID uint, permission string) (bool, error) {
	var user AuthUser
	//Get the user object from the authProvider.Database
	err := authProvider.Database.Find(&user, userID).Error
	if err != nil {
		return false, err
	}
	return authProvider.CheckPermissionLogic(permission, user.Permissions), err

}

//CheckPermissionLogic method that contains logic used to process permission checks
func (authProvider AuthProvider) CheckPermissionLogic(permissionReq string, userPermissions []AuthPermission) bool {
	//Split Permission Request
	permReqParts := strings.Split(permissionReq, ".")
	for _, userPerm := range userPermissions {
		userPermParts := strings.Split(userPerm.Permission, ".")
		userPermPartCount := len(userPermParts)
		for ri, permReqPart := range permReqParts {
			//Check if the requested permission is too long
			if (ri+1) > userPermPartCount {
				break
			}
			//Check if the user permission at this section is a wildcard
			if userPermParts[ri] == "*" {
				return true
			}
			//Check if the indexed parts match
			if permReqPart != userPermParts[ri] {
				break
			}
			//If all other tests pass and this is the last piece, this permission works
			if (ri+1) == len(permReqParts) {
				return true
			}
		}
	}
	return false
}