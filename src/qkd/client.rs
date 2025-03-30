use rand::{thread_rng, Rng};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure buffer for storing key material
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureBuffer {
    #[zeroize(skip)]
    pub id: String,
    pub data: Vec<u8>,
}

/// QKD Client for retrieving quantum keys
///
/// This is a mock implementation for testing.
/// In a real implementation, this would connect to a QKD device or API.
#[derive(Clone)]
pub struct QkdClient {
    endpoint: String,
    auth_token: Option<String>,
}

impl QkdClient {
    /// Create a new QKD client
    pub fn new(endpoint: &str, auth_token: Option<&str>) -> Result<Self, String> {
        Ok(Self {
            endpoint: endpoint.to_string(),
            auth_token: auth_token.map(String::from),
        })
    }

    /// Get a key by ID
    ///
    /// In a real implementation, this would retrieve the key from a QKD device.
    /// This mock implementation generates random bytes for testing.
    pub fn get_key(&self, key_id: &str) -> Result<SecureBuffer, String> {
        // Check if auth token is required (example endpoint that requires auth)
        if self.endpoint.contains("auth-required") && self.auth_token.is_none() {
            return Err("Authentication required".to_string());
        }

        // Simulate key retrieval delay
        std::thread::sleep(std::time::Duration::from_millis(50));

        // In a real implementation, this would contact the QKD system
        // For testing, we generate a random key
        let mut rng = thread_rng();
        let mut data = vec![0u8; 32];
        rng.fill(&mut data[..]);

        Ok(SecureBuffer {
            id: key_id.to_string(),
            data,
        })
    }

    /// Get the endpoint URL
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Check if authenticated
    pub fn is_authenticated(&self) -> bool {
        self.auth_token.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_client() {
        let client = QkdClient::new("https://qkd-server.example.com", None).unwrap();
        assert_eq!(client.endpoint(), "https://qkd-server.example.com");
        assert!(!client.is_authenticated());
    }

    #[test]
    fn test_get_key() {
        let client = QkdClient::new("https://qkd-server.example.com", None).unwrap();
        let key = client.get_key("test-key").unwrap();
        assert_eq!(key.id, "test-key");
        assert_eq!(key.data.len(), 32);
    }
}
