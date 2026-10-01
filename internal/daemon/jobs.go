package daemon

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// JobState is the lifecycle state of a background job.
type JobState string

// Job states.
const (
	JobRunning JobState = "running"
	JobDone    JobState = "done"
	JobFailed  JobState = "failed"
	JobKilled  JobState = "killed"
	// JobDenied means the scope gate refused the work. It is distinct from failed because a
	// denial is a correct outcome, not a malfunction, and a report should be able to tell
	// them apart.
	JobDenied JobState = "denied"
)

// Terminal reports whether the job has finished.
func (s JobState) Terminal() bool { return s != JobRunning }

// Job is a unit of background work.
//
// Every attack is a job. Commands return a job ID immediately and never block the prompt -
// an operator holding a directional antenna cannot be waiting on a blocked terminal, and a
// closet deployment has no prompt at all.
type Job struct {
	ID      string     `json:"id"`
	Kind    string     `json:"kind"`
	Target  string     `json:"target,omitempty"`
	State   JobState   `json:"state"`
	Started time.Time  `json:"started"`
	Ended   *time.Time `json:"ended,omitempty"`
	Error   string     `json:"error,omitempty"`
	Result  any        `json:"result,omitempty"`
	// Detail is a short operator-facing progress line.
	Detail string `json:"detail,omitempty"`
}

// Summariser is a job result that can describe its own outcome in one line.
//
// Implemented by every result an operator would otherwise have to open to understand: a
// campaign, a WPS attempt, a certificate harvest. The summary is what the job list shows and
// what the completion event carries into the log.
type Summariser interface {
	Summary() string
}

// Elapsed returns how long the job ran, or has been running.
func (j Job) Elapsed(now time.Time) time.Duration {
	if j.Ended != nil {
		return j.Ended.Sub(j.Started)
	}
	return now.Sub(j.Started)
}

type jobEntry struct {
	job    Job
	cancel context.CancelFunc
}

// JobManager runs and tracks background jobs.
type JobManager struct {
	mu     sync.RWMutex
	jobs   map[string]*jobEntry
	nextID atomic.Uint64

	// maxRetained bounds how many completed jobs are kept. A multi-day run issuing a
	// solicitation every few minutes would otherwise grow this table without limit.
	maxRetained int

	// onUpdate is called when a job changes state, so the daemon can push an event.
	onUpdate func(Job)
}

// DefaultMaxRetainedJobs is how many finished jobs are kept for `jobs`.
const DefaultMaxRetainedJobs = 200

// ErrNoJob is returned when a job ID does not exist.
var ErrNoJob = errors.New("daemon: no such job")

// NewJobManager builds a job manager. onUpdate may be nil.
func NewJobManager(onUpdate func(Job)) *JobManager {
	return &JobManager{
		jobs:        make(map[string]*jobEntry),
		maxRetained: DefaultMaxRetainedJobs,
		onUpdate:    onUpdate,
	}
}

// Start launches fn in the background and returns the job immediately.
//
// parent should be the daemon's context, so that shutting the daemon down cancels every
// running job - but note that a *client* disconnecting does not: the daemon owns the work,
// and an operator whose SSH session drops must come back to a still-running engagement.
func (m *JobManager) Start(parent context.Context, kind, target string, fn func(context.Context) (any, error)) Job {
	id := fmt.Sprintf("%d", m.nextID.Add(1))
	ctx, cancel := context.WithCancel(parent)

	job := Job{
		ID:      id,
		Kind:    kind,
		Target:  target,
		State:   JobRunning,
		Started: time.Now(),
	}

	m.mu.Lock()
	m.jobs[id] = &jobEntry{job: job, cancel: cancel}
	m.pruneLocked()
	m.mu.Unlock()

	m.notify(job)

	go func() {
		defer cancel()

		result, err := fn(ctx)
		ended := time.Now()

		m.mu.Lock()
		entry, ok := m.jobs[id]
		if !ok {
			m.mu.Unlock()
			return
		}
		// A job already marked killed keeps that state: the operator's intent is more
		// informative than the cancellation error the function returned as a result.
		if entry.job.State == JobKilled {
			entry.job.Ended = &ended
			finished := entry.job
			m.mu.Unlock()
			m.notify(finished)
			return
		}

		entry.job.Ended = &ended
		entry.job.Result = result
		// The result's own one-line summary becomes the job's detail, so a completed job says
		// what it found rather than only that it finished. "job 3 done: wps a4:2b:8c:11:22:33"
		// is not an answer to "did the PIN come out"; it left the operator to go and read a
		// JSON blob to find out whether anything had happened.
		if s, ok := result.(Summariser); ok {
			if line := s.Summary(); line != "" {
				entry.job.Detail = line
			}
		}
		switch {
		case err == nil:
			entry.job.State = JobDone
		case errors.Is(err, context.Canceled):
			entry.job.State = JobKilled
		default:
			entry.job.State = JobFailed
			entry.job.Error = err.Error()
			if isScopeDenial(err) {
				entry.job.State = JobDenied
			}
		}
		finished := entry.job
		m.mu.Unlock()

		m.notify(finished)
	}()

	return job
}

// SetDetail updates a running job's progress line.
func (m *JobManager) SetDetail(id, detail string) {
	m.mu.Lock()
	entry, ok := m.jobs[id]
	if ok {
		entry.job.Detail = detail
	}
	m.mu.Unlock()
}

// Kill cancels a running job.
func (m *JobManager) Kill(id string) error {
	m.mu.Lock()
	entry, ok := m.jobs[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNoJob, id)
	}
	if entry.job.State.Terminal() {
		state := entry.job.State
		m.mu.Unlock()
		return fmt.Errorf("daemon: job %s already finished (%s)", id, state)
	}
	entry.job.State = JobKilled
	cancel := entry.cancel
	killed := entry.job
	m.mu.Unlock()

	cancel()
	m.notify(killed)
	return nil
}

// KillAll cancels every running job. Used during shutdown so no attack outlives the daemon.
func (m *JobManager) KillAll() int {
	m.mu.Lock()
	var cancels []context.CancelFunc
	for _, entry := range m.jobs {
		if !entry.job.State.Terminal() {
			entry.job.State = JobKilled
			cancels = append(cancels, entry.cancel)
		}
	}
	m.mu.Unlock()

	for _, c := range cancels {
		c()
	}
	return len(cancels)
}

// Get returns one job.
func (m *JobManager) Get(id string) (Job, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.jobs[id]
	if !ok {
		return Job{}, fmt.Errorf("%w: %s", ErrNoJob, id)
	}
	return entry.job, nil
}

// List returns every tracked job, newest first.
func (m *JobManager) List() []Job {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]Job, 0, len(m.jobs))
	for _, entry := range m.jobs {
		out = append(out, entry.job)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Started.Equal(out[j].Started) {
			return out[i].Started.After(out[j].Started)
		}
		return out[i].ID > out[j].ID
	})
	return out
}

// RunningCount returns how many jobs are currently running, for the status header.
func (m *JobManager) RunningCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	n := 0
	for _, entry := range m.jobs {
		if !entry.job.State.Terminal() {
			n++
		}
	}
	return n
}

// pruneLocked drops the oldest finished jobs once the table is over capacity. Running jobs
// are never pruned.
func (m *JobManager) pruneLocked() {
	if len(m.jobs) <= m.maxRetained {
		return
	}

	type finished struct {
		id string
		at time.Time
	}
	var done []finished
	for id, entry := range m.jobs {
		if entry.job.State.Terminal() && entry.job.Ended != nil {
			done = append(done, finished{id, *entry.job.Ended})
		}
	}
	sort.Slice(done, func(i, j int) bool { return done[i].at.Before(done[j].at) })

	for _, f := range done {
		if len(m.jobs) <= m.maxRetained {
			return
		}
		delete(m.jobs, f.id)
	}
}

func (m *JobManager) notify(j Job) {
	if m.onUpdate != nil {
		m.onUpdate(j)
	}
}
