package hypervisor

import (
	"aster/billing/serviceapi"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestGuestReinstallUsesDurablePasswordHashWithoutPlaintext(t *testing.T) {
	m, runner, task := guestFixture(t)
	password := "Checkout-to-VM-regression!2026"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		t.Fatal(err)
	}
	request := guestTask(m, task, "4", "reinstall", serviceapi.Params{ImageID: "ubuntu22", PasswordHash: string(hash)})
	if request.Guest.PasswordRequired || !request.Guest.Valid("reinstall") {
		t.Fatal("prehashed bootstrap incorrectly requires ephemeral plaintext")
	}
	if result := submit(t, m, request); result.Status != "succeeded" {
		t.Fatal(result)
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	seed, err := os.ReadFile(filepath.Join(i.Directory, "user-data"))
	if err != nil || !strings.Contains(string(seed), string(hash)) || !strings.Contains(string(seed), "ssh_pwauth: true") {
		t.Fatal("approved password hash did not reach cloud-init")
	}
	if runner.inputCalls != 0 {
		t.Fatal("prehashed bootstrap tried to hash a missing plaintext password")
	}
	assertNoGuestSecret(t, m, password)
}
