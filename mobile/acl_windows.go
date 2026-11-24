//go:build windows

package mobile

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	sidLocalSystem    = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
)

func allowedSIDs() ([]*windows.SID, error) {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return nil, err
	}
	systemSID, err := windows.StringToSid(sidLocalSystem)
	if err != nil {
		return nil, err
	}
	adminSID, err := windows.StringToSid(sidAdministrators)
	if err != nil {
		return nil, err
	}
	return []*windows.SID{u.User.Sid, systemSID, adminSID}, nil
}

func restrictPath(path string, isDir bool) error {
	sids, err := allowedSIDs()
	if err != nil {
		return err
	}

	var inheritance uint32
	if isDir {
		inheritance = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}

	entries := make([]windows.EXPLICIT_ACCESS, len(sids))
	for i, sid := range sids {
		entries[i] = windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}

	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}

	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
}

func isPrivatePath(path string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return false, err
	}
	// x/sys returns a copy in Go memory (it frees the system buffer itself): never LocalFree it.

	control, _, err := sd.Control()
	if err != nil {
		return false, err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return false, nil
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	if dacl == nil || dacl.AceCount == 0 {
		return false, nil
	}

	sids, err := allowedSIDs()
	if err != nil {
		return false, err
	}

	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, err
		}
		aceSid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // G103: the SID starts at SidStart inside the ACE (documented ACCESS_ALLOWED_ACE layout)
		var matched bool
		for _, sid := range sids {
			if windows.EqualSid(aceSid, sid) {
				matched = true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}
