// Copyright (c) 2014-2020 Canonical Ltd
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 3 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package overlord

import (
	"context"
	"fmt"
	"runtime/trace"
	"sync"

	"github.com/canonical/pebble/internals/logger"
	"github.com/canonical/pebble/internals/overlord/state"
)

// StateManager is implemented by types responsible for observing
// the system and manipulating it to reflect the desired state.
type StateManager interface {
	// Ensure forces a complete evaluation of the current state.
	// See StateEngine.Ensure for more details.
	Ensure(ctx context.Context) error
}

// StateStarterUp is optionally implemented by StateManager that have expensive
// initialization to perform before the main Overlord loop.
type StateStarterUp interface {
	// StartUp asks manager to perform any expensive initialization.
	StartUp() error
}

// StateWaiter is optionally implemented by StateManagers that have running
// activities that can be waited.
type StateWaiter interface {
	// Wait asks manager to wait for all running activities to finish.
	Wait()
}

// StateStopper is optionally implemented by StateManagers that have
// running activities that can be terminated.
type StateStopper interface {
	// Stop asks the manager to terminate all activities running
	// concurrently.  It must not return before these activities
	// are finished.
	Stop()
}

// StateEngine controls the dispatching of state changes to state managers.
//
// Most of the actual work performed by the state engine is in fact done
// by the individual managers registered. These managers must be able to
// cope with Ensure calls in any order, coordinating among themselves
// solely via the state.
type StateEngine struct {
	state     *state.State
	stopped   bool
	startedUp bool
	// managers in use
	mgrLock  sync.Mutex
	managers []StateManager
}

// NewStateEngine returns a new state engine.
func NewStateEngine(s *state.State) *StateEngine {
	return &StateEngine{
		state: s,
	}
}

// State returns the current system state.
func (se *StateEngine) State() *state.State {
	return se.state
}

type startupError struct {
	errs []error
}

func (e *startupError) Error() string {
	return fmt.Sprintf("state startup errors: %v", e.errs)
}

// StartUp asks all managers to perform any expensive initialization. It is a noop after the first invocation.
func (se *StateEngine) StartUp(ctx context.Context) error {
	ctx, end := trace.NewTask(ctx, "pebble.state.startup")
	defer end.End()
	se.mgrLock.Lock()
	defer se.mgrLock.Unlock()
	if se.startedUp {
		return nil
	}
	se.startedUp = true
	var errs []error
	for _, m := range se.managers {
		if starterUp, ok := m.(StateStarterUp); ok {
			region := trace.StartRegion(ctx, fmt.Sprintf("pebble.manager.startup %T", m))
			err := starterUp.StartUp()
			region.End()
			if err != nil {
				trace.Logf(ctx, "error", "manager=%T error=%v", m, err)
				errs = append(errs, err)
			}
		}
	}
	if len(errs) != 0 {
		return &startupError{errs}
	}
	return nil
}

type ensureError struct {
	errs []error
}

func (e *ensureError) Error() string {
	return fmt.Sprintf("state ensure errors: %v", e.errs)
}

// Ensure asks every manager to ensure that they are doing the necessary
// work to put the current desired system state in place by calling their
// respective Ensure methods.
//
// Managers must evaluate the desired state completely when they receive
// that request, and report whether they found any critical issues. They
// must not perform long running activities during that operation, though.
// These should be performed in properly tracked changes and tasks.
func (se *StateEngine) Ensure(ctx context.Context) error {
	ctx, end := trace.NewTask(ctx, "pebble.ensure")
	defer end.End()
	se.mgrLock.Lock()
	defer se.mgrLock.Unlock()
	if !se.startedUp {
		return fmt.Errorf("state engine skipped startup")
	}
	if se.stopped {
		return fmt.Errorf("state engine already stopped")
	}
	var errs []error
	for _, m := range se.managers {
		region := trace.StartRegion(ctx, fmt.Sprintf("pebble.ensure %T", m))
		err := m.Ensure(ctx)
		region.End()
		if err != nil {
			trace.Logf(ctx, "error", "manager=%T error=%v", m, err)
			logger.Noticef("State ensure error: %v", err)
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return &ensureError{errs}
	}
	return nil
}

// AddManager adds the provided manager to take part in state operations.
func (se *StateEngine) AddManager(m StateManager) {
	se.mgrLock.Lock()
	defer se.mgrLock.Unlock()
	se.managers = append(se.managers, m)
}

// Wait waits for all managers current activities.
func (se *StateEngine) Wait(ctx context.Context) {
	ctx, end := trace.NewTask(ctx, "pebble.state.wait")
	defer end.End()
	se.mgrLock.Lock()
	defer se.mgrLock.Unlock()
	if se.stopped {
		return
	}
	for _, m := range se.managers {
		if waiter, ok := m.(StateWaiter); ok {
			region := trace.StartRegion(ctx, fmt.Sprintf("pebble.manager.wait %T", m))
			waiter.Wait()
			region.End()
		}
	}
}

// Stop asks all managers to terminate activities running concurrently.
func (se *StateEngine) Stop(ctx context.Context) {
	ctx, end := trace.NewTask(ctx, "pebble.state.stop")
	defer end.End()
	se.mgrLock.Lock()
	defer se.mgrLock.Unlock()
	if se.stopped {
		return
	}
	// Stop managers in reverse order to how they were added. Managers should
	// not have dependencies on each other, but stopping in reverse order is
	// least surprising.
	for i := len(se.managers) - 1; i >= 0; i-- {
		m := se.managers[i]
		if stopper, ok := m.(StateStopper); ok {
			logger.Debugf("State engine is stopping %T", m)
			region := trace.StartRegion(ctx, fmt.Sprintf("pebble.manager.stop %T", m))
			stopper.Stop()
			region.End()
		}
	}
	se.stopped = true
}
