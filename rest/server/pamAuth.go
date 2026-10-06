////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2019 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
//  its subsidiaries.                                                         //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

package server

import (
	"bufio"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang/glog"
	//"github.com/msteinert/pam"
	"golang.org/x/crypto/ssh"
)

/*
type UserCredential struct {
	Username string
	Password string
}

//PAM conversation handler.
func (u UserCredential) PAMConvHandler(s pam.Style, msg string) (string, error) {

	switch s {
	case pam.PromptEchoOff:
		return u.Password, nil
	case pam.PromptEchoOn:
		return u.Password, nil
	case pam.ErrorMsg:
		return "", nil
	case pam.TextInfo:
		return "", nil
	default:
		return "", errors.New("unrecognized conversation message style")
	}
}

// PAMAuthenticate performs PAM authentication for the user credentials provided
func (u UserCredential) PAMAuthenticate() error {
	tx, err := pam.StartFunc("login", u.Username, u.PAMConvHandler)
	if err != nil {
		return err
	}
	return tx.Authenticate(0)
}

func PAMAuthUser(u string, p string) error {

	cred := UserCredential{u, p}
	err := cred.PAMAuthenticate()
	return err
}
*/

// hostEtcDir is the host's /etc, bind-mounted read-only into the container.
var hostEtcDir = "/host_etc"

// readHostDB returns the colon-separated fields of each line of a host passwd/group file.
func readHostDB(name string) [][]string {
	f, err := os.Open(filepath.Join(hostEtcDir, name))
	if err != nil {
		glog.Errorf("Failed to read host %s; %v", name, err)
		return nil
	}
	defer f.Close()
	var entries [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fields := strings.Split(sc.Text(), ":"); len(fields) >= 4 {
			entries = append(entries, fields)
		}
	}
	return entries
}

// IsAdminGroup reports whether username is in the host admin user's primary group.
func IsAdminGroup(username string) bool {
	userGid, adminGid := "", ""
	for _, e := range readHostDB("passwd") {
		if e[0] == username {
			userGid = e[3]
		}
		if e[0] == "admin" {
			adminGid = e[3]
		}
	}
	glog.V(2).Infof("User:%s, gid=%s, admin gid=%s", username, userGid, adminGid)
	if adminGid == "" {
		return false
	}
	if userGid == adminGid {
		return true
	}
	for _, e := range readHostDB("group") {
		if e[2] != adminGid {
			continue
		}
		for _, m := range strings.Split(e[3], ",") {
			if m == username {
				return true
			}
		}
	}
	return false
}

func PAMAuthenAndAuthor(r *http.Request, rc *RequestContext) error {

	username, passwd, authOK := r.BasicAuth()
	if authOK == false {
		glog.Warningf("[%s] User info not present", rc.ID)
		return httpError(http.StatusUnauthorized, "")
	}

	glog.Infof("[%s] Received user=%s", rc.ID, username)

	/*
	 * mgmt-framework container does not have access to /etc/passwd, /etc/group,
	 * /etc/shadow and /etc/tacplus_conf files of host. One option is to share
	 * /etc of host with /etc of container. For now disable this and use ssh
	 * for authentication.
	 */
	/* err := PAMAuthUser(username, passwd)
	    if err != nil {
			log.Printf("Authentication failed. user=%s, error:%s", username, err.Error())
	        return err
	    }*/

	//Use ssh for authentication.
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(passwd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	_, err := ssh.Dial("tcp", "127.0.0.1:22", config)
	if err != nil {
		glog.Infof("[%s] Failed to authenticate; %v", rc.ID, err)
		return httpError(http.StatusUnauthorized, "")
	}

	glog.Infof("[%s] Authentication passed. user=%s ", rc.ID, username)

	//Allow SET request only if user belong to admin group
	if isWriteOperation(r) && IsAdminGroup(username) == false {
		glog.Warningf("[%s] Not an admin; cannot allow %s", rc.ID, r.Method)
		return httpError(http.StatusForbidden, "Not an admin user")
	}

	glog.Infof("[%s] Authorization passed", rc.ID)
	return nil
}

// isWriteOperation checks if the HTTP request is a write operation
func isWriteOperation(r *http.Request) bool {
	m := r.Method
	return m == "POST" || m == "PUT" || m == "PATCH" || m == "DELETE"
}

// authMiddleware function creates a middleware for request
// authentication and authorization. This middleware will return
// 401 response if authentication fails and 403 if authorization
// fails.
func authMiddleware(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config := getRouterConfig(r)
		if config == nil || !config.AuthEnable {
			inner.ServeHTTP(w, r)
			return
		}

		rc, r := GetContext(r)
		err := PAMAuthenAndAuthor(r, rc)
		if err != nil {
			writeErrorResponse(w, r, err)
		} else {
			inner.ServeHTTP(w, r)
		}
	})
}
