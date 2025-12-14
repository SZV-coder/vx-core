//go:build darwin

package x_darwin

import (
	"github.com/5vnetwork/vx-core/common/redirect"
)

func RedirectStderr(path string) error {
	return redirect.RedirectStderr(path)
}
