package policy

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// JobStatus represents the status of a job
type JobStatus string

const (
	// JobStatusRunning indicates the job is currently running
	JobStatusRunning JobStatus = "running"
	// JobStatusCompleted indicates the job completed successfully
	JobStatusCompleted JobStatus = "completed"
	// JobStatusFailed indicates the job failed with an error
	JobStatusFailed JobStatus = "failed"
)

// Job represents a single job execution
type Job struct {
	ID          string    `json:"id"`
	Status      JobStatus `json:"status"`
	Reason      string    `json:"reason,omitempty"`
	EntityCount int       `json:"entity_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// JobStore manages jobs in memory
type JobStore struct {
	mu   sync.RWMutex
	jobs map[string][]*Job // policyName -> jobs (max 5)
}

const maxJobsPerPolicy = 5

// NewJobStore creates a new JobStore
func NewJobStore() *JobStore {
	return &JobStore{
		jobs: make(map[string][]*Job),
	}
}

// CreateJob creates a new job for the given policy and returns it
func (js *JobStore) CreateJob(policyName string) *Job {
	js.mu.Lock()
	defer js.mu.Unlock()

	now := time.Now()
	job := &Job{
		ID:        uuid.New().String(),
		Status:    JobStatusRunning,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Add job to the policy's job list
	jobs := js.jobs[policyName]
	jobs = append(jobs, job)

	// Keep only the last maxJobsPerPolicy jobs
	if len(jobs) > maxJobsPerPolicy {
		jobs = jobs[len(jobs)-maxJobsPerPolicy:]
	}

	js.jobs[policyName] = jobs
	return job
}

// UpdateJob updates the status of a job
func (js *JobStore) UpdateJob(policyName, jobID string, status JobStatus, err error, entityCount int) {
	js.mu.Lock()
	defer js.mu.Unlock()

	jobs := js.jobs[policyName]
	for _, job := range jobs {
		if job.ID == jobID {
			job.Status = status
			job.EntityCount = entityCount
			job.UpdatedAt = time.Now()
			if err != nil {
				job.Reason = err.Error()
			}
			return
		}
	}
}

// GetJobsForPolicy returns all jobs for a given policy
func (js *JobStore) GetJobsForPolicy(policyName string) []*Job {
	js.mu.RLock()
	defer js.mu.RUnlock()

	jobs := js.jobs[policyName]
	// Return a copy to avoid race conditions
	result := make([]*Job, len(jobs))
	copy(result, jobs)
	return result
}

// GetAllPoliciesWithJobs returns all policies with their jobs
func (js *JobStore) GetAllPoliciesWithJobs() map[string][]*Job {
	js.mu.RLock()
	defer js.mu.RUnlock()

	result := make(map[string][]*Job)
	for policyName, jobs := range js.jobs {
		// Return a copy to avoid race conditions
		jobsCopy := make([]*Job, len(jobs))
		copy(jobsCopy, jobs)
		result[policyName] = jobsCopy
	}
	return result
}
