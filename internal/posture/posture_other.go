//go:build !linux && !windows

package posture

import (
	"runtime"

	"github.com/yuky2020/opensase/pkg/api"
)

func collect() api.Posture {
	return api.Posture{
		OS:            runtime.GOOS,
		ClientVersion: clientVersion(),
	}
}
