package controllerbackup

import (
	"filippo.io/age"
	"io"
)

func encryptWriter(w io.Writer, key string) (io.WriteCloser, error) {
	r, e := age.NewScryptRecipient(key)
	if e != nil {
		return nil, e
	}
	r.SetWorkFactor(18)
	return age.Encrypt(w, r)
}
