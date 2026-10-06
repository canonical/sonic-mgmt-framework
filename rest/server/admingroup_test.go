package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsAdminGroup(t *testing.T) {
	dir := t.TempDir()
	passwd := "root:x:0:0:root:/root:/bin/bash\n" +
		"admin:x:1000:1000:admin:/home/admin:/bin/bash\n" +
		"ops:x:1001:1000::/home/ops:/bin/bash\n" +
		"viewer:x:1002:1002::/home/viewer:/bin/bash\n" +
		"helper:x:1003:1003::/home/helper:/bin/bash\n"
	group := "root:x:0:\nsudo:x:27:admin,viewer\nadmin:x:1000:helper\nviewer:x:1002:\nhelper:x:1003:\n"
	os.WriteFile(filepath.Join(dir, "passwd"), []byte(passwd), 0644)
	os.WriteFile(filepath.Join(dir, "group"), []byte(group), 0644)

	saved := hostEtcDir
	hostEtcDir = dir
	defer func() { hostEtcDir = saved }()

	for user, want := range map[string]bool{
		"admin":  true,  // primary group
		"ops":    true,  // primary group is admin's
		"helper": true,  // supplementary member of admin's group
		"viewer": false, // sudo only
		"nobody": false, // not on the host
	} {
		if got := IsAdminGroup(user); got != want {
			t.Errorf("IsAdminGroup(%q) = %v, want %v", user, got, want)
		}
	}

	hostEtcDir = filepath.Join(dir, "missing")
	if IsAdminGroup("admin") {
		t.Error("IsAdminGroup must be false when the host files are unreadable")
	}
}
