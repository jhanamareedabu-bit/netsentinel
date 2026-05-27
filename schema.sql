-- DROP TYPES IF EXIST
DROP TYPE IF EXISTS user_role CASCADE;
DROP TYPE IF EXISTS account_status CASCADE;

-- CREATE TYPES AGAIN
CREATE TYPE user_role AS ENUM ('Viewer', 'Admin');
CREATE TYPE account_status AS ENUM ('Active', 'Locked');

-- USERS TABLE
CREATE TABLE IF NOT EXISTS Users(
user_id SERIAL PRIMARY KEY,
username VARCHAR(50) UNIQUE NOT NULL,
full_name VARCHAR(100) NOT NULL,
password_hash TEXT NOT NULL,
role VARCHAR(20) DEFAULT 'User',
status VARCHAR(20) DEFAULT 'Active',
failed_attempts INT DEFAULT 0,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- DEVICES TABLE
CREATE TABLE IF NOT EXISTS Devices (
    device_id SERIAL PRIMARY KEY,
    device_name VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    mac_address VARCHAR(17),
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- LOGS TABLE
CREATE TABLE IF NOT EXISTS ActivityLogs (
    log_id SERIAL PRIMARY KEY,
    user_id INT,
    device_id INT,
    action_description VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);