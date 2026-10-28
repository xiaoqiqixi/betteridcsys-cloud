package controllerbackup

import (
	"aster/cloud/internal/control"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// SourceConsoleEntrypoint describes authenticated historical service arguments,
// not an approval to expose a listener or trust the source TLS certificate now.
// A nil entrypoint is unknown (legacy archive), NOT an API-only installation.
type SourceConsoleEntrypoint struct {
	Enabled    bool   `json:"enabled"`
	Origin     string `json:"origin"`
	UnitSHA256 string `json:"unit_sha256"`
}

const sourceControllerUnit = "source/controller.service"
const maxSourceControllerUnit = 16384

// Match the entire managed installer format, not a permissive systemd parser.
// The archived unit is data only and is never installed or executed. Changed
// installer templates must add an explicit format here and pass the native
// installer/export interoperability gate; no fallback guesses at ExecStart.
const sourceUnitHead = `[Unit]
Description=Aster Cloud controller (root-reviewed native install)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=`

const sourceUnitTail = `
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
LockPersonality=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictRealtime=true
SystemCallArchitectures=native
LimitNOFILE=1024
TimeoutStopSec=45
StandardOutput=journal
StandardError=journal
LogRateLimitIntervalSec=30s
LogRateLimitBurst=1000
PrivateDevices=true
CapabilityBoundingSet=
AmbientCapabilities=
MemoryMax=256M
TasksMax=64
StateDirectory=aster-controller
StateDirectoryMode=0700
RestartPreventExitStatus=78

[Install]
WantedBy=multi-user.target
`

func validConsoleOrigin(origin string) bool {
	if len(origin) > 2048 || !regexp.MustCompile(`^https://[A-Za-z0-9.\[\]:-]+$`).MatchString(origin) {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(u.Host, ":") {
		return false
	}
	if strings.HasPrefix(u.Host, "[") {
		if net.ParseIP(u.Hostname()) == nil || !strings.Contains(u.Hostname(), ":") {
			return false
		}
	} else if strings.Contains(u.Hostname(), ":") {
		return false
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}
	return true
}

func parseSourceConsole(raw []byte, installed sourceInstallation) (*SourceConsoleEntrypoint, error) {
	if len(raw) == 0 || len(raw) > maxSourceControllerUnit || !shaPattern.MatchString(installed.BundleSHA256) ||
		!regexp.MustCompile(`^0\.[0-9]+\.[0-9]+-(?:dev(?:\.[0-9]+)?|rc\.[0-9]+)$`).MatchString(installed.Version) {
		return nil, ErrInvalid
	}
	command, headOK := strings.CutPrefix(string(raw), sourceUnitHead)
	command, tailOK := strings.CutSuffix(command, sourceUnitTail)
	if !headOK || !tailOK {
		return nil, ErrInvalid
	}
	version := "/opt/aster-cloud/controller/versions/" + installed.Version + "-" + installed.BundleSHA256[:16]
	extra, ok := strings.CutPrefix(command, version+"/bin/aster-controller serve -config /etc/aster-controller/config.json")
	if !ok {
		return nil, ErrInvalid
	}
	entry := &SourceConsoleEntrypoint{UnitSHA256: digestBytes(raw)}
	if extra == "" {
		return entry, nil
	}
	origin, prefixOK := strings.CutPrefix(extra, " -console-origin ")
	origin, suffixOK := strings.CutSuffix(origin, " -ui-dir "+version+"/ui")
	if !prefixOK || !suffixOK || !validConsoleOrigin(origin) {
		return nil, ErrInvalid
	}
	entry.Enabled, entry.Origin = true, origin
	return entry, nil
}

func (a *Archive) sourceConsole(installed sourceInstallation, units []sourceUnit) (*SourceConsoleEntrypoint, error) {
	if _, exists := a.files[sourceControllerUnit]; !exists {
		return nil, nil
	}
	raw, err := a.readSmall(sourceControllerUnit, maxSourceControllerUnit)
	if err != nil {
		return nil, ErrInvalid
	}
	for _, unit := range units {
		if unit.Name == "aster-controller.service" && unit.SHA256 == digestBytes(raw) {
			return parseSourceConsole(raw, installed)
		}
	}
	return nil, ErrInvalid
}

// Read only the coordinator's saved original, not the now-masked service or a
// path chosen in an archive/request. The host-operation and runtime locks are
// already held by ExportSealedSource's caller. All reads remain read-only.
func exportSourceConsole(planRaw, installationRaw []byte, config control.Config, operation string) ([]byte, error) {
	var plan sourcePlan
	var installed sourceInstallation
	if !operationID.MatchString(operation) || !exactSourceRecord(planRaw, &plan) || plan.Schema != 1 || !validSourceUnits(plan.Units, config) ||
		!exactSourceRecord(installationRaw, &installed) || installed.Component != "controller" || installed.Schema != 1 ||
		plan.Identity.InstallationSHA256 != digestBytes(installationRaw) {
		return nil, ErrInvalid
	}
	for _, unit := range plan.Units {
		if unit.Name != "aster-controller.service" {
			continue
		}
		path := "/etc/systemd/system/.aster-migration-" + operation + "-" + strconv.Itoa(unit.Index) + ".saved"
		before, err := os.Lstat(path)
		if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0644 {
			return nil, ErrInvalid
		}
		native, ok := before.Sys().(*syscall.Stat_t)
		if !ok || native.Uid != 0 || native.Nlink != 1 || uint64(native.Dev) != unit.OriginalInode.Device || uint64(native.Ino) != unit.OriginalInode.Inode {
			return nil, ErrInvalid
		}
		raw, err := control.ReadProtected(path, false, maxSourceControllerUnit)
		after, statErr := os.Lstat(path)
		if err != nil || statErr != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || digestBytes(raw) != unit.SHA256 {
			return nil, ErrInvalid
		}
		if _, err := parseSourceConsole(raw, installed); err != nil {
			return nil, ErrInvalid
		}
		return raw, nil
	}
	return nil, ErrInvalid
}
