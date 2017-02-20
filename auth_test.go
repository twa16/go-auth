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
	"fmt"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"os"
	"testing"
	"time"
)

var authProvider AuthProvider

func init() {
	//os.Remove("./auth-test.db")
	authProvider = AuthProvider{}
	db, err := gorm.Open("sqlite3", "./auth-test.db")
	db.DropTable(&User{})
	db.DropTable(&Permission{})
	db.DropTable(&UserMetadata{})
	db.DropTable(&Session{})
	if err != nil {
		fmt.Println("Error starting DB: " + err.Error())
		os.Exit(1)
	}
	//db.LogMode(true)
	authProvider.Database = db
	authProvider.Startup()
}

func TestPermissionLogicSimpleEquality(t *testing.T) {
	var userPermissions []Permission
	userPermission := Permission{}
	userPermission.Permission = "a.b.c"
	userPermissions = append(userPermissions, userPermission)

	res := authProvider.CheckPermissionLogic("a.b.c", userPermissions)
	if res == false {
		t.Fail()
	}
}

func TestPermissionLogicLevelOneWildcard(t *testing.T) {
	var userPermissions []Permission
	userPermission := Permission{}
	userPermission.Permission = "*"
	userPermissions = append(userPermissions, userPermission)

	res := authProvider.CheckPermissionLogic("a.b.c", userPermissions)
	if res == false {
		t.Fail()
	}
}

func TestPermissionLogicLevelTwoWildcard(t *testing.T) {
	var userPermissions []Permission
	userPermission := Permission{}
	userPermission.Permission = "a.*"
	userPermissions = append(userPermissions, userPermission)

	res := authProvider.CheckPermissionLogic("a.b.c", userPermissions)
	if res == false {
		t.Fail()
	}
}

func TestPermissionLogicLevelThreeWildcard(t *testing.T) {
	var userPermissions []Permission
	userPermission := Permission{}
	userPermission.Permission = "a.b.*"
	userPermissions = append(userPermissions, userPermission)

	res := authProvider.CheckPermissionLogic("a.b.c", userPermissions)
	if res == false {
		t.Fail()
	}
}

func TestPermissionLogicTooShort(t *testing.T) {
	var userPermissions []Permission
	userPermission := Permission{}
	userPermission.Permission = "a.b"
	userPermissions = append(userPermissions, userPermission)

	res := authProvider.CheckPermissionLogic("a.b.c", userPermissions)
	if res == true {
		t.Fail()
	}
}

func TestPermissionLogicSimpleMismatch(t *testing.T) {
	var userPermissions []Permission
	userPermission := Permission{}
	userPermission.Permission = "b.b.c"
	userPermissions = append(userPermissions, userPermission)

	res := authProvider.CheckPermissionLogic("a.b.c", userPermissions)
	if res == true {
		t.Fail()
	}
}

func TestPermissionLogicSimpleMultirule(t *testing.T) {
	var userPermissions []Permission
	userPermission := Permission{}
	userPermission.Permission = "b.b.c"
	userPermissions = append(userPermissions, userPermission)
	userPermission.Permission = "a.b.c"
	userPermissions = append(userPermissions, userPermission)

	res := authProvider.CheckPermissionLogic("a.b.c", userPermissions)
	if res == false {
		t.Fail()
	}
}

func TestPermissionLogicSimpleMultiruleMatchFirst(t *testing.T) {
	var userPermissions []Permission
	userPermission := Permission{}
	userPermission.Permission = "a.b.c"
	userPermissions = append(userPermissions, userPermission)
	userPermission.Permission = "e.b.c"
	userPermissions = append(userPermissions, userPermission)

	res := authProvider.CheckPermissionLogic("a.b.c", userPermissions)
	if res == false {
		t.Fail()
	}
}

func TestPermissionLogicWildcardMultirule(t *testing.T) {
	var userPermissions []Permission
	userPermission := Permission{}
	userPermission.Permission = "b.b.c"
	userPermissions = append(userPermissions, userPermission)
	userPermission.Permission = "a.*"
	userPermissions = append(userPermissions, userPermission)

	res := authProvider.CheckPermissionLogic("a.b.c", userPermissions)
	if res == false {
		t.Fail()
	}
}

func TestPermissionLogicSimpleMultiruleNoMatch(t *testing.T) {
	var userPermissions []Permission
	userPermission := Permission{}
	userPermission.Permission = "f.b.c"
	userPermissions = append(userPermissions, userPermission)
	userPermission.Permission = "d.b.c"
	userPermissions = append(userPermissions, userPermission)
	userPermission.Permission = "d.e.c"
	userPermissions = append(userPermissions, userPermission)

	res := authProvider.CheckPermissionLogic("a.b.c", userPermissions)
	if res == true {
		t.Fail()
	}
}

func TestUserCreationSimple(t *testing.T) {
	var userToCreate User
	userToCreate.Username = "testuser"
	userToCreate.FirstName = "Test"
	userToCreate.LastName = "User"
	userToCreate.Email = "test@testcompany.com"
	userToCreate.PhoneNumber = "1234567890"
	userToCreate.Permissions = []Permission{{Permission: "test.pass"}}

	userToCreate, err := authProvider.CreateUser(userToCreate)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestGetUser(t *testing.T) {
	user, err := authProvider.GetUser("testuser")
	if err != nil {
		t.Fatal(err.Error())
	}
	if user.Email != "test@testcompany.com" {
		t.Fail()
	}
	if len(user.Permissions) == 0 {
		t.Error("Permissions association broken by username")
	}

	userByID, err := authProvider.GetUserByID(user.ID)
	if err != nil {
		t.Fatal(err.Error())
	}
	if userByID.Email != "test@testcompany.com" {
		t.Fail()
	}
	if len(userByID.Permissions) == 0 {
		t.Error("Permissions association broken by id")
	}
}

func TestSetPassword(t *testing.T) {
	user, err := authProvider.GetUser("testuser")
	if err != nil {
		t.Fatal(err.Error())
	}
	err = authProvider.SetUserPassword(user, "testtest")
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestLogin(t *testing.T) {
	goodLogin, err := authProvider.CheckLogin("testuser", "testtest")
	if err != nil {
		t.Fatal(err.Error())
	}
	if goodLogin == false {
		t.Fatal("Password Check Error")
	}
}

var scuserID uint
var scsessionToken string
func TestSessionCreation(t *testing.T) {
	user, _ := authProvider.GetUser("testuser")
	session, err := authProvider.GenerateSessionKey(user.ID, false)
	if err != nil {
		t.Fatal(err.Error())
	}
	if session.AuthenticationToken == "" {
		t.Fatal("Failed to generate session token")
	} else {
		scuserID = session.AuthUserID
		scsessionToken = session.AuthenticationToken
	}
}

func TestSessionCheck(t *testing.T) {
	scresp, err := authProvider.CheckSessionKey(scsessionToken)
	if err != nil {
		t.Fatal(err.Error())
	}
	if scresp.AuthSession == nil {
		t.Fatal("Session lookup failed")
	}
	if scresp.AuthSession.AuthUserID != scuserID {
		t.Fatal("Session userID mismatch")
	}
	if scresp.IsExpired {
		t.Fatal("Session expired too soon")
	}
}

func TestCheckUserPermissionMethod(t *testing.T) {
	user, _ := authProvider.GetUser("testuser")
	hasPerm, err := authProvider.CheckPermission(user.ID, "test.pass")
	if err != nil {
		t.Fatal(err.Error())
	}
	if hasPerm == false {
		t.Fatal("Permission Check Helper Failed")
	}
}

func TestSessionAccessUpdate(t *testing.T) {
	scresp, err := authProvider.CheckSessionKey(scsessionToken)
	if err != nil {
		t.Fatal(err.Error())
	}
	authProvider.UpdateSessionAccessTime(*scresp.AuthSession)
	scresp, _ = authProvider.CheckSessionKey(scsessionToken)
	curTime := time.Now().Unix()
	if curTime - scresp.AuthSession.LastSeen > 5 {
		t.Fatal("Session access update failed")
	}
}
