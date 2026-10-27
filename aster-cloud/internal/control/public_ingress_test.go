package control

import (
	"aster/cloud/internal/overlayproto"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func ingressOperationFixture(t *testing.T) PublicIngressOperation {
	t.Helper()
	actor, vm, key := strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)
	now := time.Now().UTC().Truncate(time.Microsecond)
	policy, e := overlayproto.CanonicalPublicIngress(overlayproto.PublicIngressPolicy{Schema: 1, InstanceID: vm, OwnerRef: actor, Revision: 1, Rules: []overlayproto.PublicIngressRule{}})
	if e != nil {
		t.Fatal(e)
	}
	v := publicIngressView(policy)
	v.State, v.OperationID, v.UpdatedAt, v.Supported = "active", key, &now, true
	v.EffectiveRevision = ingressRevision(1)
	raw, _ := json.Marshal(PublicIngressInput{ExpectedRevision: ingressRevision(0), Rules: []overlayproto.PublicIngressRule{}})
	return PublicIngressOperation{ID: key, ActorID: actor, Action: "public_ingress.update", TargetInstanceID: vm, RequestSHA256: publicOperationDigest("public_ingress.update", vm, raw), Request: raw, Result: PublicIngressResult{Policy: v}, CreatedAt: now}
}
func TestPublicIngressStrictInputAndOriginalBindingBody(t *testing.T) {
	for _, body := range []string{`{}`, `{"expected_revision":0}`, `{"expected_revision":0,"rules":null}`, `{"expected_revision":0,"rules":[],"owner_ref":"a"}`, `{"expected_revision":0,"rules":[],"rules":[]}`, `{"expected_revision":0,"Rules":[]}`} {
		var in PublicIngressInput
		if strict([]byte(body), &in) {
			t.Fatal("loose rules contract accepted", body)
		}
	}
	for _, body := range []string{`{"expected_revision":null,"rules":[]}`, `{"expected_revision":9007199254740991,"rules":[]}`} {
		var in PublicIngressInput
		if !strict([]byte(body), &in) {
			t.Fatal("JSON shape unexpectedly changed", body)
		}
		if _, _, _, e := (&SQLStore{}).SetPublicIngress(t.Context(), Config{}, strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32), in, time.Now().UTC()); e != ErrInput {
			t.Fatal("invalid CAS was not rejected before DB", body, e)
		}
	}
	old := `{"instance_id":"` + strings.Repeat("2", 32) + `","expected_generation":0}`
	var in publicResourceBindingInput
	if !strictPublicIP([]byte(old), &in) || in.ExpectedIngressRevision != nil || in.ExpectedGeneration == nil {
		t.Fatal("old two-field binding rejected")
	}
	raw, _ := json.Marshal(in)
	if string(raw) != old {
		t.Fatal("old immutable binding bytes changed", string(raw))
	}
	newBody := strings.TrimSuffix(old, "}") + `,"expected_ingress_revision":0}`
	if !strictPublicIP([]byte(newBody), &in) || in.ExpectedIngressRevision == nil || *in.ExpectedIngressRevision != 0 {
		t.Fatal("explicit revision zero rejected")
	}
	for _, body := range []string{strings.TrimSuffix(old, "}") + `,"expected_ingress_revision":null}`, strings.TrimSuffix(old, "}") + `,"expected_ingress_revision":0,"expected_ingress_revision":0}`, strings.TrimSuffix(old, "}") + `,"Expected_ingress_revision":0}`} {
		if strictPublicIP([]byte(body), &in) {
			t.Fatal("ambiguous binding CAS accepted", body)
		}
	}
}
func TestPublicIngressImmutableResultStrictTimeAndMetadata(t *testing.T) {
	op := ingressOperationFixture(t)
	if !publicIngressResultValid(op) {
		t.Fatal("fixture invalid")
	}
	raw, _ := json.Marshal(op.Result)
	var out PublicIngressResult
	if !strictPublicIP(raw, &out) || !reflect.DeepEqual(out, op.Result) {
		t.Fatal("immutable ACK timestamp rejected")
	}
	for _, edit := range []func(*PublicIngressOperation){
		func(o *PublicIngressOperation) { o.Result.Policy.SHA256 = strings.Repeat("0", 64) },
		func(o *PublicIngressOperation) { o.Result.Policy.InstanceID = strings.Repeat("4", 32) },
		func(o *PublicIngressOperation) { o.Result.Policy.Revision = 0 },
		func(o *PublicIngressOperation) { o.Result.Policy.Rules = nil },
		func(o *PublicIngressOperation) { o.Result.Policy.EffectiveRevision = nil },
		func(o *PublicIngressOperation) { o.Result.Policy.EffectiveRevision = ingressRevision(0) },
		func(o *PublicIngressOperation) { o.Result.Policy.OperationID = strings.Repeat("5", 32) },
		func(o *PublicIngressOperation) { o.Result.Policy.UpdatedAt = nil },
		func(o *PublicIngressOperation) { at := o.CreatedAt.Add(time.Second); o.Result.Policy.UpdatedAt = &at },
		func(o *PublicIngressOperation) { o.Result.Policy.LegacyUnrestricted = true },
		func(o *PublicIngressOperation) { o.Result.Policy.UnsupportedReason = "UPGRADE_REQUIRED" },
		func(o *PublicIngressOperation) { o.Result.Policy.Supported = false },
		func(o *PublicIngressOperation) { o.RequestSHA256 = strings.Repeat("0", 64) },
		func(o *PublicIngressOperation) { o.Action = "resource.bind" },
	} {
		mutated := ingressOperationFixture(t)
		edit(&mutated)
		if publicIngressResultValid(mutated) {
			t.Fatal("corrupt immutable ACK accepted", mutated)
		}
	}
	op.Result.Policy.State = "pending"
	op.Result.Policy.EffectiveRevision = nil
	op.Result.Policy.EpochID = strings.Repeat("4", 32)
	op.Result.Policy.BoundResourceID = strings.Repeat("5", 32)
	if !publicIngressResultValid(op) {
		t.Fatal("valid pending ACK rejected")
	}
	op.Result.Policy.LegacyUnrestricted = true
	if !publicIngressResultValid(op) {
		t.Fatal("legacy upgrade ACK cannot hide old unrestricted mapping")
	}
	op.Result.Policy.Supported = false
	op.Result.Policy.UnsupportedReason = "UPGRADE_REQUIRED"
	if publicIngressResultValid(op) {
		t.Fatal("unsupported ACK planned new ingress epoch")
	}
}

type ingressOperationRow struct{ op PublicIngressOperation }

func (row ingressOperationRow) Scan(dest ...any) error {
	o := row.op
	*dest[0].(*string), *dest[1].(*string), *dest[2].(*string), *dest[3].(*string), *dest[4].(*string) = o.ID, o.ActorID, o.Action, o.TargetInstanceID, o.RequestSHA256
	*dest[5].(*json.RawMessage) = append(json.RawMessage{}, o.Request...)
	raw, _ := json.Marshal(o.Result)
	*dest[6].(*[]byte) = raw
	*dest[7].(*time.Time) = o.CreatedAt
	return nil
}
func TestPublicIngressOperationScannerAcceptsExactFrozenTimestamp(t *testing.T) {
	o := ingressOperationFixture(t)
	got, e := scanPublicIngressOperation(ingressOperationRow{o})
	if e != nil || !reflect.DeepEqual(got, o) {
		t.Fatal("valid persistent operation cannot replay", e)
	}
	o.Result.Policy.UpdatedAt = nil
	if _, e = scanPublicIngressOperation(ingressOperationRow{o}); e != ErrState {
		t.Fatal("corrupt persisted time accepted", e)
	}
}

func TestPublicIngressAdmissionTTLStaysControllerLocal(t *testing.T) {
	approval := OverlayAdmission{ControllerID: "main", RootClusters: []OverlayCluster{{ClusterID: "private"}}}
	old, _ := json.Marshal(approval)
	approval.HeartbeatTTLSeconds = 60
	withTTL, _ := json.Marshal(approval)
	if string(old) != string(withTTL) {
		t.Fatal("controller-local TTL changed immutable wire", string(withTTL))
	}
}
