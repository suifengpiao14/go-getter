package getter

import (
	"net/url"
	"regexp"
)

// Note that we do not have an SSH-getter currently so this file serves
// only to hold the detectSSH helper that is used by other detectors.

// sshPattern matches SCP-like SSH patterns (user@host:path)
var sshPattern = regexp.MustCompile("^(?:([^@]+)@)?([^:]+):/?(.+)$")

// detectSSH determines if the src string matches an SSH-like URL and
// converts it into a net.URL compatible string. This returns nil if the
// string doesn't match the SSH pattern.
//
// This function is tested indirectly via detect_git_test.go
func detectSSH(src string) (*url.URL, error) {
	matched := sshPattern.FindStringSubmatch(src)
	if matched == nil {
		return nil, nil
	}

	user := matched[1]
	host := matched[2]
	path := matched[3]
	tmpU, err := url.Parse(path)
	if err != nil {
		return nil, err
	}
	var u url.URL
	u.Scheme = "ssh"
	u.User = url.User(user)
	u.Host = host
	u.Path = tmpU.Path
	u.RawQuery = tmpU.RawQuery
	u.Fragment = tmpU.Fragment

	return &u, nil
}
