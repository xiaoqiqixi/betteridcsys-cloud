package main

import (
	"aster/cloud/internal/controllerbackup"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func configurationCertificate(t *testing.T, hostname string, after time.Time) ([]byte, []byte) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(44), Subject: pkix.Name{CommonName: "Configuration plan test"}, DNSNames: []string{hostname},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: after, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}

func TestAuthenticatedTargetConfigurationPlan(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	files := sourceWithNode(t, sourceFixture(t))
	sourceCert, sourceKey := configurationCertificate(t, "source.invalid", time.Now().Add(72*time.Hour))
	sourceReplaceMaterial(t, files, "tls_cert_file", sourceCert)
	sourceReplaceMaterial(t, files, "tls_key_file", sourceKey)
	operation, planSHA := strings.Repeat("a", 32), strings.Repeat("c", 64)
	key := controllerbackup.KeyPrefix + strings.Repeat("9", 64)
	archive, recovery := filepath.Join(dir, "backup.age"), filepath.Join(dir, "recovery.key")
	if err := os.WriteFile(archive, sourceArchive(t, files, key), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recovery, []byte(key+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	target := controllerbackup.RuntimeTarget{Directory: dir, PlanSHA256: planSHA,
		DSN: "aster_r_" + operation[:23] + ":new-private-target-password@unix(/run/mysqld/mysqld.sock)/aster_cloud_restore_" + operation}
	cert, privateKey := configurationCertificate(t, "console.target.invalid", time.Now().Add(72*time.Hour))
	if err := os.WriteFile(filepath.Join(dir, "configuration-tls.crt"), cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "configuration-tls.key"), privateKey, 0600); err != nil {
		t.Fatal(err)
	}
	request := sourceJSON(map[string]any{"schema": 1, "operation_id": operation, "target_plan_sha256": planSHA,
		"console_enabled": true, "console_origin": "https://console.target.invalid:9555", "listen": "127.0.0.1:9555", "tls_mode": "replacement"})
	err = controllerbackup.WithVerifiedArchive(archive, recovery, "source-one", operation, dir, func(a *controllerbackup.Archive) error {
		if _, err := a.RestoreRuntimeMaterials(target); err != nil {
			return err
		}
		before := map[string][]byte{}
		entries, err := os.ReadDir(filepath.Join(dir, "runtime"))
		if err != nil {
			return err
		}
		for _, e := range entries {
			b, err := os.ReadFile(filepath.Join(dir, "runtime", e.Name()))
			if err != nil {
				return err
			}
			before[e.Name()] = b
		}
		plan, err := a.PlanConfiguration(target, request, strings.Repeat("e", 64))
		if err != nil {
			t.Fatalf("explicit target configuration could not be planned: %v", err)
		}
		if plan.Schema != 1 || plan.ControllerID != "source-one" || plan.OperationID != operation || plan.TargetPlanSHA256 != planSHA ||
			plan.SourceConsole != nil || !plan.ConsoleEnabled || plan.ConsoleOrigin != "https://console.target.invalid:9555" || plan.Listen != "127.0.0.1:9555" ||
			plan.SessionIntentSHA256 != strings.Repeat("e", 64) || plan.RequestSHA256 != sourceHash(request) || len(plan.Files) != 4 ||
			plan.CanonicalConfigurationSHA256 == "" || plan.CanonicalConfigurationSHA256 == plan.SourceConfigurationSHA256 {
			t.Fatalf("configuration binding incomplete: %+v", plan)
		}
		encoded, err := json.Marshal(plan)
		if err != nil {
			return err
		}
		for _, secret := range [][]byte{privateKey, []byte("new-private-target-password"), []byte("private-password"), []byte("/unavailable-source/")} {
			if bytes.Contains(encoded, secret) {
				t.Fatal("private material exposed in plan")
			}
		}
		for name, want := range before {
			got, err := os.ReadFile(filepath.Join(dir, "runtime", name))
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("read-only plan changed material stage")
			}
		}
		for _, name := range []string{"configuration-started.json", "configuration-approval.json", "aster-controller"} {
			if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
				t.Fatal("plan wrote publication state")
			}
		}
		t.Run("reject garbage before certificate PEM", func(t *testing.T) {
			path := filepath.Join(dir, "configuration-tls.crt")
			if err := os.WriteFile(path, append([]byte("unreviewed prefix\n"), cert...), 0600); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.WriteFile(path, cert, 0600); err != nil {
					t.Fatal(err)
				}
			}()
			if _, err := a.PlanConfiguration(target, request, strings.Repeat("e", 64)); err == nil {
				t.Fatal("certificate framing discarded unreviewed bytes")
			}
		})
		for name, update := range map[string]func(map[string]any){
			"wrong operation":                    func(r map[string]any) { r["operation_id"] = strings.Repeat("b", 32) },
			"wrong target plan":                  func(r map[string]any) { r["target_plan_sha256"] = strings.Repeat("b", 64) },
			"missing console decision":           func(r map[string]any) { delete(r, "console_enabled") },
			"disabled but origin set":            func(r map[string]any) { r["console_enabled"] = false },
			"TLS source with unused replacement": func(r map[string]any) { r["tls_mode"] = "source" },
			"arbitrary TLS path":                 func(r map[string]any) { r["tls_cert_file"] = "/tmp/foreign" },
			"listen hostname":                    func(r map[string]any) { r["listen"] = "localhost:9555" },
			"ephemeral listener":                 func(r map[string]any) { r["listen"] = "127.0.0.1:0" },
			"multicast listener":                 func(r map[string]any) { r["listen"] = "224.0.0.1:9555" },
			"wrong HTTPS hostname":               func(r map[string]any) { r["console_origin"] = "https://other.invalid:9555" },
			"insecure origin":                    func(r map[string]any) { r["console_origin"] = "http://console.target.invalid:9555" },
			"unknown TLS mode":                   func(r map[string]any) { r["tls_mode"] = "force" },
		} {
			t.Run(name, func(t *testing.T) {
				var r map[string]any
				if err := json.Unmarshal(request, &r); err != nil {
					t.Fatal(err)
				}
				update(r)
				if _, err := a.PlanConfiguration(target, sourceJSON(r), strings.Repeat("e", 64)); err == nil {
					t.Fatal("invalid protected request accepted")
				}
			})
		}
		for name, invalid := range map[string][]byte{
			"duplicate key": bytes.Replace(request, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
			"case alias":    bytes.Replace(request, []byte(`"schema"`), []byte(`"Schema"`), 1),
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := a.PlanConfiguration(target, invalid, strings.Repeat("e", 64)); err == nil {
					t.Fatal("ambiguous request accepted")
				}
			})
		}
		certPath, keyPath := filepath.Join(dir, "configuration-tls.crt"), filepath.Join(dir, "configuration-tls.key")
		t.Run("TLS pair and lifetime must really verify", func(t *testing.T) {
			for _, deadline := range []time.Time{time.Now().Add(-time.Minute), time.Now().Add(time.Hour)} {
				badCert, badKey := configurationCertificate(t, "console.target.invalid", deadline)
				if err := os.WriteFile(certPath, badCert, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(keyPath, badKey, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := a.PlanConfiguration(target, request, strings.Repeat("e", 64)); err == nil {
					t.Fatal("expired or short-lived TLS approved")
				}
			}
			if err := os.WriteFile(certPath, cert, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := a.PlanConfiguration(target, request, strings.Repeat("e", 64)); err == nil {
				t.Fatal("wrong private key approved")
			}
			if err := os.WriteFile(keyPath, append([]byte("unreviewed prefix\n"), privateKey...), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := a.PlanConfiguration(target, request, strings.Repeat("e", 64)); err == nil {
				t.Fatal("key framing approved")
			}
			if err := os.WriteFile(keyPath, privateKey, 0600); err != nil {
				t.Fatal(err)
			}
		})
		t.Run("replacement key remains private and single-link", func(t *testing.T) {
			if err := os.Chmod(keyPath, 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := a.PlanConfiguration(target, request, strings.Repeat("e", 64)); err == nil {
				t.Fatal("public private key accepted")
			}
			if err := os.Chmod(keyPath, 0600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(dir, "other-key")
			if err := os.Link(keyPath, link); err != nil {
				t.Fatal(err)
			}
			if _, err := a.PlanConfiguration(target, request, strings.Repeat("e", 64)); err == nil {
				t.Fatal("shared private key accepted")
			}
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
		})
		t.Run("source TLS requires explicit request too", func(t *testing.T) {
			if err := os.Remove(certPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(keyPath); err != nil {
				t.Fatal(err)
			}
			var r map[string]any
			if err := json.Unmarshal(request, &r); err != nil {
				t.Fatal(err)
			}
			r["tls_mode"], r["console_origin"] = "source", "https://source.invalid:9555"
			p, err := a.PlanConfiguration(target, sourceJSON(r), strings.Repeat("e", 64))
			if err != nil || p.TLSMode != "source" || p.SourceConsole != nil || p.ConsoleOrigin != "https://source.invalid:9555" {
				t.Fatal("explicit source TLS plan rejected", err)
			}
			if err := os.WriteFile(certPath, cert, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyPath, privateKey, 0600); err != nil {
				t.Fatal(err)
			}
		})
		again, err := a.PlanConfiguration(target, request, strings.Repeat("e", 64))
		if err != nil {
			t.Fatal(err)
		}
		againBytes, err := json.Marshal(again)
		if err != nil || !bytes.Equal(againBytes, encoded) {
			t.Fatal("read-only reentry changed the same plan", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
