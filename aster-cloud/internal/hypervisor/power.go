package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"errors"
	"time"
)

var errPowerObservationTimeout = errors.New("power observation timed out")
var errGuestShutdownTimeout = errors.New("guest shutdown timed out")

func (m *Manager) shutdownTimeout() time.Duration {
	return time.Duration(m.Config.ShutdownTimeoutSeconds) * time.Second
}

// observePower never retries a command or hides a failed observation. The
// deadline also bounds a stuck virsh read; only a successful final read can
// establish a graceful timeout with an unchanged running guest.
func (m *Manager) observePower(ctx context.Context, domain, desired string, timeout time.Duration) (string, error) {
	wait, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	finalRead := func() (string, error) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		final, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		state, err := m.state(final, domain)
		if err != nil {
			return "", err
		}
		if state == desired {
			return state, nil
		}
		return state, errPowerObservationTimeout
	}
	for {
		if wait.Err() != nil {
			return finalRead()
		}
		state, err := m.state(wait, domain)
		if err != nil {
			// The local observation budget may expire between the check above
			// and virsh returning. Use the same bounded final read as the timer
			// branch; this never repeats shutdown/destroy/start.
			if wait.Err() != nil && ctx.Err() == nil {
				return finalRead()
			}
			return "", err
		}
		if state == desired {
			return state, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-wait.Done():
			return finalRead()
		case <-tick.C:
		}
	}
}

func (m *Manager) reboot(ctx context.Context, i Instance, force bool) (string, error) {
	if _, err := m.virsh(ctx, "shutdown", i.Domain); err != nil {
		return "", err
	}
	state, err := m.observePower(ctx, i.Domain, "shut off", m.shutdownTimeout())
	if errors.Is(err, errPowerObservationTimeout) && nodeproto.ValidObservedState(state) {
		if !force {
			return state, errGuestShutdownTimeout
		}
		// Recheck metadata before the explicitly authorized escalation. A failed
		// destroy is never retried, even if the guest later appears shut off.
		if err = m.assertOwned(ctx, i); err != nil {
			return "", err
		}
		if _, err = m.virsh(ctx, "destroy", i.Domain); err != nil {
			return "", err
		}
		state, err = m.observePower(ctx, i.Domain, "shut off", 10*time.Second)
	}
	if err != nil {
		return state, err
	}
	if err = m.assertOwned(ctx, i); err != nil {
		return "", err
	}
	if _, err = m.virsh(ctx, "start", i.Domain); err != nil {
		return "", err
	}
	return m.observePower(ctx, i.Domain, "running", 10*time.Second)
}
