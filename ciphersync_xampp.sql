-- CipherSync MySQL/XAMPP bootstrap
-- Import this file in phpMyAdmin.

CREATE DATABASE IF NOT EXISTS `dlp_db`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
USE `dlp_db`;

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";

-- Drop tables first for clean re-import
DROP TABLE IF EXISTS `alerts`;
DROP TABLE IF EXISTS `incidents`;
DROP TABLE IF EXISTS `policies`;
DROP TABLE IF EXISTS `devices`;
DROP TABLE IF EXISTS `users`;

-- USERS
CREATE TABLE `users` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(100) NOT NULL,
  `email` VARCHAR(191) NOT NULL,
  `phone` VARCHAR(30) DEFAULT NULL,
  `password` VARCHAR(255) NOT NULL,
  `role` VARCHAR(50) DEFAULT 'User',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_users_username` (`username`),
  UNIQUE KEY `uq_users_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- POLICIES
CREATE TABLE `policies` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `policy_name` VARCHAR(255) NOT NULL,
  `category` VARCHAR(100) NOT NULL,
  `status` VARCHAR(50) NOT NULL,
  `last_modified` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- DEVICES
CREATE TABLE `devices` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `device_name` VARCHAR(255) NOT NULL,
  `device_type` VARCHAR(100) NOT NULL,
  `status` VARCHAR(50) NOT NULL,
  `last_seen` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- INCIDENTS
CREATE TABLE `incidents` (
  `incident_id` VARCHAR(50) NOT NULL,
  `description` TEXT NOT NULL,
  `severity` VARCHAR(50) NOT NULL,
  `status` VARCHAR(50) NOT NULL,
  `notes` TEXT,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`incident_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ALERTS
CREATE TABLE `alerts` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `feed` VARCHAR(255) NOT NULL,
  `activity` VARCHAR(255) NOT NULL,
  `time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `status` VARCHAR(50) NOT NULL,
  `risk` VARCHAR(50) NOT NULL,
  `details` TEXT,
  `source` VARCHAR(255),
  `user` VARCHAR(255),
  `threat_type` VARCHAR(100),
  `threat_actor` VARCHAR(255),
  PRIMARY KEY (`id`),
  KEY `idx_alerts_time` (`time`),
  KEY `idx_alerts_status` (`status`),
  KEY `idx_alerts_threat_type` (`threat_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed user (matches app login/forgot/change password flows)
INSERT INTO `users` (`username`, `email`, `phone`, `password`, `role`) VALUES
('admin', 'admin@ciphersync.com', '09171234567', 'admin123', 'Administrator');

-- Seed policies
INSERT INTO `policies` (`policy_name`, `category`, `status`, `last_modified`) VALUES
('Smart Home PII Scan', 'Privacy', 'Active', NOW()),
('Outbound Data Block', 'Network', 'Active', DATE_SUB(NOW(), INTERVAL 2 DAY)),
('Device Trust List', 'Access Control', 'Active', DATE_SUB(NOW(), INTERVAL 5 DAY));

-- Seed devices
INSERT INTO `devices` (`device_name`, `device_type`, `status`, `last_seen`) VALUES
('Smart Fridge', 'IoT', 'Online', NOW()),
('Home Server', 'Server', 'Online', NOW()),
('Living Room Speaker', 'IoT', 'Online', DATE_SUB(NOW(), INTERVAL 15 MINUTE)),
('Security Hub', 'Gateway', 'Online', NOW());

-- Seed incidents
INSERT INTO `incidents` (`incident_id`, `description`, `severity`, `status`, `notes`, `updated_at`) VALUES
('INC-2026-001', 'Repeated credit card pattern on smart fridge API', 'Critical', 'Open', '', NOW()),
('INC-2026-002', 'Admin credential exposure in exported logs', 'High', 'Investigating', 'Awaiting user confirmation', NOW()),
('INC-2026-003', 'Guest device phishing link via voice assistant', 'High', 'Mitigated', 'Blocked at gateway', DATE_SUB(NOW(), INTERVAL 1 DAY));

-- Seed alerts
INSERT INTO `alerts` (`feed`, `activity`, `time`, `status`, `risk`, `details`, `source`, `user`, `threat_type`, `threat_actor`) VALUES
('DLP x Smart Fridge', 'Payment Info Leak', DATE_SUB(NOW(), INTERVAL 2 HOUR), 'blocked', 'High Risk', 'Credit card data detected.', 'Smart Fridge', 'Family-Account', 'Data Leaks', '192.168.1.55'),
('DLP x Home Server', 'Sensitive Log Export', DATE_SUB(NOW(), INTERVAL 5 HOUR), 'prompted', 'Medium Risk', 'System log export contains credentials.', 'Home Server', 'Admin', 'Unauthorized Access', 'Admin-Account'),
('DLP x Speaker', 'Voice Privacy Alert', DATE_SUB(NOW(), INTERVAL 1 DAY), 'tagged', 'Low Risk', 'Voice data contains sensitive keywords.', 'Speaker', 'Child-Room', 'Policy Violations', '192.168.1.12'),
('DLP x Security Hub', 'WiFi Config Leak', DATE_SUB(NOW(), INTERVAL 2 DAY), 'blocked', 'High Risk', 'Attempt to broadcast WiFi SSID.', 'Security Hub', 'Unknown-Device', 'Data Leaks', '182.45.12.99'),
('DLP x Home Server', 'Malware Signature Blocked', DATE_SUB(NOW(), INTERVAL 3 DAY), 'blocked', 'High Risk', 'Malicious binary download intercepted.', 'Home Server', 'Admin', 'Malware', '192.168.1.100');
