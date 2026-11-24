//go:build !windows

package mobile

import "os"

func restrictPath(_ string, _ bool) error {
	return nil
}

func isPrivatePath(path string) (bool, error) {
	st, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return st.Mode().Perm()&0o077 == 0, nil
}
