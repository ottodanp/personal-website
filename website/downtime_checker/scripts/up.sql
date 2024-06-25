CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id INT AUTO_INCREMENT PRIMARY KEY,
    url VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS checks (
    check_id INT AUTO_INCREMENT PRIMARY KEY,
    endpoint_id INT NOT NULL,
    status_code INT NOT NULL,
    response_time_ms INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id)
);

CREATE INDEX idx_created_at ON checks (created_at);
CREATE INDEX idx_endpoint_id ON checks (endpoint_id);
