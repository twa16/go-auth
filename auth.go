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
)

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

func CreateUser(db *gorm.DB, user AuthUser) (AuthUser, error) {
	err := db.Create(&user).Error
	return user, err
}

func GetUser(db *gorm.DB, username string) (AuthUser, error) {
	var user AuthUser
	err := db.Where("username = ?", username).First(&user).Error
	if err != nil {
		return user, err
	}
	user, err = GetUserByID(db, user.ID)
	return user, err
}

func GetUserByID(db *gorm.DB, userID uint) (AuthUser, error) {
	var user AuthUser
	err := db.First(&user, userID).Error
	db.Model(&user).Related(&user.UserMetaData)
	db.Model(&user).Related(&user.Permissions)
	db.Model(&user).Related(&user.Sessions)
	return user, err
}

//CheckLogin This function returns the user true if the credentials correspond to a user
func CheckLogin(db *gorm.DB, username string, password string) (bool, error) {
	userObject, err := GetUser(db, username)
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
func GenerateSessionKey(db *gorm.DB, userID uint, persistent bool) (AuthSession, error) {
	sessionKey := AuthSession{}
	sessionKey.AuthUserID = userID
	sessionKey.Persistent = persistent
	sessionKey.AuthenticationToken = uuid.NewV4().String()
	err := db.Create(sessionKey).Error
	return sessionKey, err
}

//CheckPermission Returns true if the user has the provided permission
func CheckPermission(db *gorm.DB, userID uint, permission string) (bool, error) {
	var user AuthUser
	//Get the user object from the db
	err := db.Find(&user, userID).Error
	if err != nil {
		return false, err
	}
	return CheckPermissionLogic(permission, user.Permissions), err

}

func CheckPermissionLogic(permissionReq string, userPermissions []AuthPermission) bool {
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