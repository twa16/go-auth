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
	"testing"
)

func TestPermissionLogicSimpleEquality(t *testing.T) {
	var userPermissions []AuthPermission
	userPermission := AuthPermission{}
	userPermission.Permission = "a.b.c"
	userPermissions = append(userPermissions, userPermission)

	res := CheckPermissionLogic("a.b.c", userPermissions)
	if res == false {
		t.Fail()
	}
}

func TestPermissionLogicLevelOneWildcard(t *testing.T) {
	var userPermissions []AuthPermission
	userPermission := AuthPermission{}
	userPermission.Permission = "*"
	userPermissions = append(userPermissions, userPermission)

	res := CheckPermissionLogic("a.b.c", userPermissions)
	if res == false {
		t.Fail()
	}
}


func TestPermissionLogicLevelTwoWildcard(t *testing.T) {
	var userPermissions []AuthPermission
	userPermission := AuthPermission{}
	userPermission.Permission = "a.*"
	userPermissions = append(userPermissions, userPermission)

	res := CheckPermissionLogic("a.b.c", userPermissions)
	if res == false {
		t.Fail()
	}
}

func TestPermissionLogicLevelThreeWildcard(t *testing.T) {
	var userPermissions []AuthPermission
	userPermission := AuthPermission{}
	userPermission.Permission = "a.b.*"
	userPermissions = append(userPermissions, userPermission)

	res := CheckPermissionLogic("a.b.c", userPermissions)
	if res == false {
		t.Fail()
	}
}

func TestPermissionLogicTooShort(t *testing.T) {
	var userPermissions []AuthPermission
	userPermission := AuthPermission{}
	userPermission.Permission = "a.b"
	userPermissions = append(userPermissions, userPermission)

	res := CheckPermissionLogic("a.b.c", userPermissions)
	if res == true {
		t.Fail()
	}
}

func TestPermissionLogicSimpleMismatch(t *testing.T) {
	var userPermissions []AuthPermission
	userPermission := AuthPermission{}
	userPermission.Permission = "b.b.c"
	userPermissions = append(userPermissions, userPermission)

	res := CheckPermissionLogic("a.b.c", userPermissions)
	if res == true {
		t.Fail()
	}
}

func TestPermissionLogicSimpleMultirule(t *testing.T) {
	var userPermissions []AuthPermission
	userPermission := AuthPermission{}
	userPermission.Permission = "b.b.c"
	userPermissions = append(userPermissions, userPermission)
	userPermission.Permission = "a.b.c"
	userPermissions = append(userPermissions, userPermission)

	res := CheckPermissionLogic("a.b.c", userPermissions)
	if res == false {
		t.Fail()
	}
}

func TestPermissionLogicSimpleMultiruleMatchFirst(t *testing.T) {
	var userPermissions []AuthPermission
	userPermission := AuthPermission{}
	userPermission.Permission = "a.b.c"
	userPermissions = append(userPermissions, userPermission)
	userPermission.Permission = "e.b.c"
	userPermissions = append(userPermissions, userPermission)

	res := CheckPermissionLogic("a.b.c", userPermissions)
	if res == false {
		t.Fail()
	}
}

func TestPermissionLogicWildcardMultirule(t *testing.T) {
	var userPermissions []AuthPermission
	userPermission := AuthPermission{}
	userPermission.Permission = "b.b.c"
	userPermissions = append(userPermissions, userPermission)
	userPermission.Permission = "a.*"
	userPermissions = append(userPermissions, userPermission)

	res := CheckPermissionLogic("a.b.c", userPermissions)
	if res == false {
		t.Fail()
	}
}

func TestPermissionLogicSimpleMultiruleNoMatch(t *testing.T) {
	var userPermissions []AuthPermission
	userPermission := AuthPermission{}
	userPermission.Permission = "f.b.c"
	userPermissions = append(userPermissions, userPermission)
	userPermission.Permission = "d.b.c"
	userPermissions = append(userPermissions, userPermission)
	userPermission.Permission = "d.e.c"
	userPermissions = append(userPermissions, userPermission)

	res := CheckPermissionLogic("a.b.c", userPermissions)
	if res == true {
		t.Fail()
	}
}

