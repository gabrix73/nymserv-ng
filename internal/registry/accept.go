package registry

import (
	"encoding/base64"
	"errors"
)

// DefaultDailyLimit is the per-alias ceiling on messages handled in one day.
// It is enforced inside the same critical section as the counter bump; the
// original implementation read the counter back *after* releasing the lock,
// which let concurrent deliveries interleave past the ceiling.
const DefaultDailyLimit = 512

var (
	// ErrReplay means the envelope digest has been seen inside the TTL.
	ErrReplay = errors.New("registry: replayed message")
	// ErrCounterNotMonotonic means the envelope counter did not advance.
	ErrCounterNotMonotonic = errors.New("registry: counter did not advance")
	// ErrRateLimited means the alias has hit its daily ceiling.
	ErrRateLimited = errors.New("registry: daily limit exceeded")
	// ErrDisabled means the alias exists but delivery is suppressed.
	ErrDisabled = errors.New("registry: alias is disabled")
)

// Accept performs every stateful inbound check for one authenticated envelope
// and persists the result before returning.
//
// The ordering and atomicity here are load-bearing:
//
//   - Identity lookup, counter check, replay check, rate limit and the state
//     update all happen under one write lock. Splitting them would let two
//     concurrent deliveries of the same message both pass.
//   - The new counter and the replay digest are written to disk *before* this
//     returns, so the caller can only release a message whose replay state is
//     already durable. A crash between acceptance and release loses the
//     message, which is the safe direction to fail.
//
// Callers must treat every returned error as the same event: drop silently,
// emit nothing. The distinct error values exist for tests and for operator
// metrics that are aggregated, never per-message.
func (s *Store) Accept(identity [KeyLen]byte, counter uint64, digest [32]byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.c == nil {
		return "", ErrSealed
	}

	var target *Nym
	for _, n := range s.c.Nyms {
		if n.Mode == ModeModern && n.IdentityKey == identity {
			target = n
			break
		}
	}
	if target == nil {
		return "", ErrNoSuchNym
	}
	if target.Flags.Has(FlagDisabled) {
		return "", ErrDisabled
	}

	if counter <= target.Counter {
		return "", ErrCounterNotMonotonic
	}

	key := base64.RawStdEncoding.EncodeToString(digest[:])
	now := nowUnix()
	if exp, ok := s.c.Replay[key]; ok && exp > now {
		return "", ErrReplay
	}

	day := Today()
	if !target.Flags.Has(FlagNoLimit) {
		// Peek at what the count would become without committing it, so a
		// rate-limited message does not consume the counter slot.
		projected := target.DayCount + 1
		if target.DayIndex != day {
			projected = 1
		}
		if projected > DefaultDailyLimit {
			return "", ErrRateLimited
		}
	}

	target.Counter = counter
	target.BumpCounter(day)
	s.c.Replay[key] = now + int64(ReplayTTL.Seconds())

	if err := s.save(); err != nil {
		return "", err
	}
	return target.Alias, nil
}

// AcceptLegacy is the equivalent for legacy nyms, which carry no counter and
// are therefore protected only by the digest cache. The weaker guarantee is
// the reason the modern envelope has a counter at all.
func (s *Store) AcceptLegacy(alias string, digest [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.c == nil {
		return ErrSealed
	}

	n, ok := s.c.Nyms[alias]
	if !ok || n.Mode != ModeLegacy {
		return ErrNoSuchNym
	}
	if n.Flags.Has(FlagDisabled) {
		return ErrDisabled
	}

	key := base64.RawStdEncoding.EncodeToString(digest[:])
	now := nowUnix()
	if exp, ok := s.c.Replay[key]; ok && exp > now {
		return ErrReplay
	}

	day := Today()
	if !n.Flags.Has(FlagNoLimit) {
		projected := n.DayCount + 1
		if n.DayIndex != day {
			projected = 1
		}
		if projected > DefaultDailyLimit {
			return ErrRateLimited
		}
	}

	n.BumpCounter(day)
	s.c.Replay[key] = now + int64(ReplayTTL.Seconds())
	return s.save()
}
