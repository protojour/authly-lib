use authly_client::{identity::Identity, Client};
use pyo3::{exceptions::PySystemError, prelude::*};

#[pyclass(module = "authly")]
struct Authly {
    tokio: tokio::runtime::Runtime,
    client: Option<Client>,
}

#[pymethods]
impl Authly {
    #[new]
    pub fn __new__() -> Self {
        Self {
            tokio: tokio::runtime::Runtime::new().unwrap(),
            client: None,
        }
    }

    pub async fn connect(&mut self, url: String, ca_path: String, id_path: String) -> PyResult<()> {
        self.tokio.block_on(async {
            let local_ca = std::fs::read(ca_path)?;
            let identity = Identity::from_pem(std::fs::read(id_path)?)
                .map_err(|err| PySystemError::new_err(err.to_string()))?;
            let client = Client::builder()
                .with_authly_local_ca_pem(local_ca)
                .map_err(|err| PySystemError::new_err(err.to_string()))?
                .with_identity(identity)
                .with_url(url)
                .connect()
                .await
                .map_err(|err| PySystemError::new_err(err.to_string()))?;
            self.client = Some(client);
            Ok(())
        })
    }

    pub fn is_connected(&self) -> bool {
        self.client.is_some()
    }
}

#[pymodule]
fn authly(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Authly>()?;

    Ok(())
}
