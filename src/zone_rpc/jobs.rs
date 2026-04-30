//! Local/dev Zone RPC job store.
//!
//! This is intentionally process-local. It lets the PoC exercise the public
//! job lifecycle before proof workers and relayer persistence are finalized.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::zone_rpc::api::{ZoneJobResponse, ZoneJobStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneJobKind {
    Proof,
    Relayer,
}

#[derive(Debug, Clone)]
pub struct LocalZoneJobStore {
    inner: Arc<LocalZoneJobStoreInner>,
}

#[derive(Debug, Default)]
struct LocalZoneJobStoreInner {
    counter: AtomicU64,
    jobs: Mutex<HashMap<String, ZoneJobResponse>>,
}

impl Default for LocalZoneJobStore {
    fn default() -> Self {
        Self {
            inner: Arc::new(LocalZoneJobStoreInner::default()),
        }
    }
}

impl LocalZoneJobStore {
    pub fn create_queued_job(&self, kind: ZoneJobKind) -> ZoneJobResponse {
        self.create_job(kind, ZoneJobStatus::Queued, None, None)
    }

    pub fn create_job(
        &self,
        kind: ZoneJobKind,
        status: ZoneJobStatus,
        result: Option<String>,
        error: Option<String>,
    ) -> ZoneJobResponse {
        let job_id = self.next_job_id(kind);
        let response = ZoneJobResponse {
            job_id: job_id.clone(),
            status,
            result,
            error,
        };
        self.inner
            .jobs
            .lock()
            .expect("zone job mutex poisoned")
            .insert(job_id, response.clone());
        response
    }

    pub fn get_job(&self, job_id: &str) -> Option<ZoneJobResponse> {
        self.inner
            .jobs
            .lock()
            .expect("zone job mutex poisoned")
            .get(job_id)
            .cloned()
    }

    pub fn upsert_job(&self, response: ZoneJobResponse) {
        self.inner
            .jobs
            .lock()
            .expect("zone job mutex poisoned")
            .insert(response.job_id.clone(), response);
    }

    fn next_job_id(&self, kind: ZoneJobKind) -> String {
        let prefix = match kind {
            ZoneJobKind::Proof => "proof",
            ZoneJobKind::Relayer => "relayer",
        };
        let id = self.inner.counter.fetch_add(1, Ordering::Relaxed) + 1;
        format!("{prefix}-{id}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_queued_jobs_by_id() {
        let store = LocalZoneJobStore::default();
        let job = store.create_queued_job(ZoneJobKind::Proof);

        assert_eq!(job.job_id, "proof-1");
        assert_eq!(job.status, ZoneJobStatus::Queued);
        assert_eq!(store.get_job(&job.job_id), Some(job));
        assert_eq!(store.get_job("missing"), None);
    }

    #[test]
    fn updates_existing_jobs() {
        let store = LocalZoneJobStore::default();
        let mut job = store.create_queued_job(ZoneJobKind::Relayer);
        job.status = ZoneJobStatus::Succeeded;
        job.result = Some("{}".to_string());

        store.upsert_job(job.clone());

        assert_eq!(store.get_job(&job.job_id), Some(job));
    }
}
