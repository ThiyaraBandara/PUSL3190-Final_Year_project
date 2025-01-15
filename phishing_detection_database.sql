CREATE DATABASE  IF NOT EXISTS `phishing_detection`;
USE `phishing_detection`;

DROP TABLE IF EXISTS `scanresults`;
DROP TABLE IF EXISTS `detectedlinks`;
DROP TABLE IF EXISTS `urls`;
CREATE TABLE `urls` (
  `url_id` int NOT NULL AUTO_INCREMENT,
  `url` varchar(255) NOT NULL,
  `html_content` LONGTEXT,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `url` (`url`),
  PRIMARY KEY (`url_id`)
);

DROP TABLE IF EXISTS `detectedlinks`;
CREATE TABLE `detectedlinks` (
  `detected_link_id` int NOT NULL AUTO_INCREMENT,
  `url_id` int DEFAULT NULL,
  `phishing_score` float DEFAULT NULL,
  `detected_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`detected_link_id`),
  KEY `url_id` (`url_id`),
  CONSTRAINT `detectedlinks_ibfk_1` FOREIGN KEY (`url_id`) REFERENCES `urls` (`url_id`)
);

DROP TABLE IF EXISTS `scanresults`;
CREATE TABLE `scanresults` (
  `scan_results_id` int NOT NULL AUTO_INCREMENT,
  `detected_link_id` int DEFAULT NULL,
  `scan_date` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `total_url_scan` int DEFAULT NULL,
  `phishing_urls_found` int DEFAULT NULL,
  `report` text,
  PRIMARY KEY (`scan_results_id`),
  KEY `detected_link_id` (`detected_link_id`),
  CONSTRAINT `scanresults_ibfk_1` FOREIGN KEY (`detected_link_id`) REFERENCES `detectedlinks` (`detected_link_id`) ON DELETE SET NULL
);
