DROP TYPE IF EXISTS user_role CASCADE;
DROP TYPE IF EXISTS account_status CASCADE;

CREATE TYPE user_role AS ENUM ('Viewer', 'Admin');
CREATE TYPE account_status AS ENUM ('Active', 'Locked');

CREATE TABLE Users(
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    password_hash TEXT NOT NULL,
    role user_role DEFAULT 'Viewer',
    status account_status DEFAULT 'Active',
    failed_attempts INT DEFAULT 0,
    last_login_ip VARCHAR(45),
    last_login_time TIMESTAMP,
    is_online BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

CREATE TABLE Devices (
    device_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES Users(user_id),
    device_name VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    mac_address VARCHAR(17),
    status VARCHAR(20) DEFAULT 'Active',
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

CREATE TABLE ActivityLogs (
    log_id SERIAL PRIMARY KEY,
    user_id INT,
    device_id INT,
    ip_address VARCHAR(45),
    log_type VARCHAR(20),
    action_description VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );