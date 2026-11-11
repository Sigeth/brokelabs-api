//! Access to the Kubernetes API: the api writes desired state (instances,
//! check runs) as custom resources and reads what the operator reports (D2).

use async_trait::async_trait;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{DeleteParams, ListParams, PostParams};
use kube::{Api, Client};
use opslab_types::conventions::{DEFAULT_INSTRUCTIONS, config_map_key};
use opslab_types::{Challenge, ChallengeInstance, CheckRun};

pub type Result<T> = std::result::Result<T, kube::Error>;

/// What the api needs from the cluster. Faked in tests.
#[async_trait]
pub trait Cluster: Send + Sync {
    /// Installed challenges.
    async fn challenges(&self) -> Result<Vec<Challenge>>;
    async fn challenge(&self, name: &str) -> Result<Option<Challenge>>;
    /// Student instructions (markdown) of an installed challenge.
    async fn instructions(&self, challenge: &Challenge) -> Result<Option<String>>;
    async fn instance(&self, name: &str) -> Result<Option<ChallengeInstance>>;
    async fn create_instance(&self, instance: &ChallengeInstance) -> Result<ChallengeInstance>;
    /// Deletes an instance; deleting a missing one is not an error.
    async fn delete_instance(&self, name: &str) -> Result<()>;
    async fn create_check_run(&self, run: &CheckRun) -> Result<CheckRun>;
}

/// The real cluster.
pub struct Kube {
    pub client: Client,
    pub instances_namespace: String,
    pub system_namespace: String,
}

impl Kube {
    fn instances(&self) -> Api<ChallengeInstance> {
        Api::namespaced(self.client.clone(), &self.instances_namespace)
    }
}

#[async_trait]
impl Cluster for Kube {
    async fn challenges(&self) -> Result<Vec<Challenge>> {
        Ok(Api::<Challenge>::all(self.client.clone())
            .list(&ListParams::default())
            .await?
            .items)
    }

    async fn challenge(&self, name: &str) -> Result<Option<Challenge>> {
        Api::<Challenge>::all(self.client.clone())
            .get_opt(name)
            .await
    }

    async fn instructions(&self, challenge: &Challenge) -> Result<Option<String>> {
        // Inline packages keep their files in a ConfigMap; OCI packages
        // (M3) will be extracted by the operator.
        let Some(cm_name) = challenge
            .spec
            .source
            .inline
            .as_ref()
            .and_then(|i| i.files_config_map.as_deref())
        else {
            return Ok(None);
        };
        let cm = Api::<ConfigMap>::namespaced(self.client.clone(), &self.system_namespace)
            .get_opt(cm_name)
            .await?;
        Ok(cm
            .and_then(|cm| cm.data)
            .and_then(|mut data| data.remove(&config_map_key(DEFAULT_INSTRUCTIONS))))
    }

    async fn instance(&self, name: &str) -> Result<Option<ChallengeInstance>> {
        self.instances().get_opt(name).await
    }

    async fn create_instance(&self, instance: &ChallengeInstance) -> Result<ChallengeInstance> {
        self.instances()
            .create(&PostParams::default(), instance)
            .await
    }

    async fn delete_instance(&self, name: &str) -> Result<()> {
        match self
            .instances()
            .delete(name, &DeleteParams::background())
            .await
        {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn create_check_run(&self, run: &CheckRun) -> Result<CheckRun> {
        Api::<CheckRun>::namespaced(self.client.clone(), &self.instances_namespace)
            .create(&PostParams::default(), run)
            .await
    }
}

#[cfg(test)]
pub mod fake {
    //! In-memory cluster for handler tests.

    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    pub struct FakeCluster {
        pub challenges: Mutex<Vec<Challenge>>,
        pub instructions: Mutex<BTreeMap<String, String>>,
        pub instances: Mutex<BTreeMap<String, ChallengeInstance>>,
        pub check_runs: Mutex<Vec<CheckRun>>,
    }

    #[async_trait]
    impl Cluster for FakeCluster {
        async fn challenges(&self) -> Result<Vec<Challenge>> {
            Ok(self.challenges.lock().unwrap().clone())
        }

        async fn challenge(&self, name: &str) -> Result<Option<Challenge>> {
            Ok(self
                .challenges
                .lock()
                .unwrap()
                .iter()
                .find(|c| c.metadata.name.as_deref() == Some(name))
                .cloned())
        }

        async fn instructions(&self, challenge: &Challenge) -> Result<Option<String>> {
            let name = challenge.metadata.name.clone().unwrap_or_default();
            Ok(self.instructions.lock().unwrap().get(&name).cloned())
        }

        async fn instance(&self, name: &str) -> Result<Option<ChallengeInstance>> {
            Ok(self.instances.lock().unwrap().get(name).cloned())
        }

        async fn create_instance(&self, instance: &ChallengeInstance) -> Result<ChallengeInstance> {
            let mut created = instance.clone();
            created.metadata.uid = Some(format!(
                "uid-{}",
                instance.metadata.name.clone().unwrap_or_default()
            ));
            self.instances.lock().unwrap().insert(
                created.metadata.name.clone().unwrap_or_default(),
                created.clone(),
            );
            Ok(created)
        }

        async fn delete_instance(&self, name: &str) -> Result<()> {
            self.instances.lock().unwrap().remove(name);
            Ok(())
        }

        async fn create_check_run(&self, run: &CheckRun) -> Result<CheckRun> {
            self.check_runs.lock().unwrap().push(run.clone());
            Ok(run.clone())
        }
    }
}
