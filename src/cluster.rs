//! Access to the Kubernetes API: the api writes desired state (instances,
//! check runs) as custom resources and reads what the operator reports (D2).

use async_trait::async_trait;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{DeleteParams, ListParams, PostParams};
use kube::{Api, Client};
use opslab_types::conventions::{DEFAULT_INSTRUCTIONS, config_map_key};
use opslab_types::{CatalogSource, Challenge, ChallengeInstance, CheckRun};

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
    /// Every instance, of every user.
    async fn instances(&self) -> Result<Vec<ChallengeInstance>>;
    async fn catalog_sources(&self) -> Result<Vec<CatalogSource>>;
    async fn create_catalog_source(&self, source: &CatalogSource) -> Result<CatalogSource>;
    /// Deletes a catalog source; its challenges and their instances go with
    /// it (D43). Deleting a missing one is not an error.
    async fn delete_catalog_source(&self, name: &str) -> Result<()>;
    /// Creates a challenge, or replaces the spec of an existing one.
    async fn put_challenge(&self, challenge: &Challenge) -> Result<Challenge>;
    /// Deletes a challenge; its instances go with it (D43).
    async fn delete_challenge(&self, name: &str) -> Result<()>;
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
        // The operator reports the ConfigMap holding the installed files,
        // whatever the source of the package (inline or registry).
        let Some(cm_name) = challenge
            .status
            .as_ref()
            .and_then(|s| s.files_config_map.as_deref())
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

    async fn instances(&self) -> Result<Vec<ChallengeInstance>> {
        Ok(self.instances().list(&ListParams::default()).await?.items)
    }

    async fn catalog_sources(&self) -> Result<Vec<CatalogSource>> {
        Ok(Api::<CatalogSource>::all(self.client.clone())
            .list(&ListParams::default())
            .await?
            .items)
    }

    async fn create_catalog_source(&self, source: &CatalogSource) -> Result<CatalogSource> {
        Api::<CatalogSource>::all(self.client.clone())
            .create(&PostParams::default(), source)
            .await
    }

    async fn delete_catalog_source(&self, name: &str) -> Result<()> {
        ignore_not_found(
            Api::<CatalogSource>::all(self.client.clone())
                .delete(name, &DeleteParams::background())
                .await,
        )
    }

    async fn put_challenge(&self, challenge: &Challenge) -> Result<Challenge> {
        let api = Api::<Challenge>::all(self.client.clone());
        let name = challenge.metadata.name.clone().unwrap_or_default();
        match api.get_opt(&name).await? {
            None => api.create(&PostParams::default(), challenge).await,
            Some(mut existing) => {
                // Replace the spec only: the operator owns the status and the
                // owner references (D43).
                existing.spec = challenge.spec.clone();
                api.replace(&name, &PostParams::default(), &existing).await
            }
        }
    }

    async fn delete_challenge(&self, name: &str) -> Result<()> {
        ignore_not_found(
            Api::<Challenge>::all(self.client.clone())
                .delete(name, &DeleteParams::background())
                .await,
        )
    }
}

fn ignore_not_found<T>(result: Result<T>) -> Result<()> {
    match result {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(e) => Err(e),
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
        pub catalog_sources: Mutex<Vec<CatalogSource>>,
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

        async fn instances(&self) -> Result<Vec<ChallengeInstance>> {
            Ok(self.instances.lock().unwrap().values().cloned().collect())
        }

        async fn catalog_sources(&self) -> Result<Vec<CatalogSource>> {
            Ok(self.catalog_sources.lock().unwrap().clone())
        }

        async fn create_catalog_source(&self, source: &CatalogSource) -> Result<CatalogSource> {
            self.catalog_sources.lock().unwrap().push(source.clone());
            Ok(source.clone())
        }

        async fn delete_catalog_source(&self, name: &str) -> Result<()> {
            // The garbage collector's cascade (D43), done by hand.
            let owned = |c: &Challenge| {
                c.spec
                    .source
                    .catalog
                    .as_ref()
                    .is_some_and(|s| s.source == name)
            };
            self.catalog_sources
                .lock()
                .unwrap()
                .retain(|s| s.metadata.name.as_deref() != Some(name));
            let removed: Vec<String> = self
                .challenges
                .lock()
                .unwrap()
                .iter()
                .filter(|c| owned(c))
                .filter_map(|c| c.metadata.name.clone())
                .collect();
            for challenge in removed {
                self.delete_challenge(&challenge).await?;
            }
            Ok(())
        }

        async fn put_challenge(&self, challenge: &Challenge) -> Result<Challenge> {
            let mut list = self.challenges.lock().unwrap();
            match list
                .iter_mut()
                .find(|c| c.metadata.name == challenge.metadata.name)
            {
                Some(existing) => existing.spec = challenge.spec.clone(),
                None => list.push(challenge.clone()),
            }
            Ok(challenge.clone())
        }

        async fn delete_challenge(&self, name: &str) -> Result<()> {
            self.challenges
                .lock()
                .unwrap()
                .retain(|c| c.metadata.name.as_deref() != Some(name));
            self.instances
                .lock()
                .unwrap()
                .retain(|_, i| i.spec.challenge != name);
            Ok(())
        }
    }
}
