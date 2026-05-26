// Copyright (c) 2026 Canonical Ltd
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

package cmdstate

import (
	"context"
	"time"

	"github.com/gorilla/websocket"
	"gopkg.in/tomb.v2"

	"github.com/canonical/pebble/internals/overlord/state"
)

// GetWorkingDir exposes getWorkingDir for testing.
var GetWorkingDir = getWorkingDir

// FakeEnviron replaces the environ function used in Exec for testing.
func FakeEnviron(f func() map[string]string) (restore func()) {
	old := environ
	environ = f
	return func() { environ = old }
}

// FakeConnectTimeout replaces connectTimeout for testing.
func FakeConnectTimeout(d time.Duration) (restore func()) {
	old := connectTimeout
	connectTimeout = d
	return func() { connectTimeout = old }
}

// NewExecSetupKey creates the cache key used to store an exec setup for a
// given task ID. Returned as any so callers can pass it to st.Cached.
func NewExecSetupKey(taskID string) any {
	return execSetupKey{taskID: taskID}
}

// DoExec exposes the doExec method for testing.
func (m *CommandManager) DoExec(
	task *state.Task,
	t *tomb.Tomb,
) error {
	return m.doExec(task, t)
}

// AddTestExecution inserts a fake execution into the manager's map and
// broadcasts the condition variable.
func (m *CommandManager) AddTestExecution(taskID string) {
	m.executionsCond.L.Lock()
	m.executions[taskID] = &execution{}
	m.executionsCond.Broadcast()
	m.executionsCond.L.Unlock()
}

// WaitTestExecution exposes waitExecution for testing, returning true when
// a non-nil execution is found.
func (m *CommandManager) WaitTestExecution(
	taskID string,
	stop <-chan struct{},
) bool {
	return m.waitExecution(taskID, stop) != nil
}

// NewTestExecution creates an execution value suitable for unit tests.
func NewTestExecution(splitStderr bool) *execution {
	e := &execution{
		splitStderr:      splitStderr,
		websockets:       make(map[string]*websocket.Conn),
		ioConnected:      make(chan struct{}),
		controlConnected: make(chan struct{}),
	}
	e.websockets[wsControl] = nil
	e.websockets[wsStdio] = nil
	if splitStderr {
		e.websockets[wsStderr] = nil
	}
	return e
}

// SignalIOConnected closes the ioConnected channel on e.
func (e *execution) SignalIOConnected() {
	close(e.ioConnected)
}

// WaitIOConnected exposes e.waitIOConnected for testing.
func (e *execution) WaitIOConnected(
	ctx context.Context,
	execID string,
) error {
	return e.waitIOConnected(ctx, execID)
}
