CREATE DATABASE rpc;

CREATE USER 'phpmyadm'@'localhost' IDENTIFIED WITH mysql_native_password BY 'QRBIhj_ojXoUuzTS65vH';

GRANT ALL ON rpc.* TO 'phpmyadm'@'localhost';

SET interactive_timeout=604800;

USE rpc;









create table cwe
(
	id varchar(30) not null,
	name text null,
	description text null,
	constraint cwe_pk
		primary key (id)
);

CREATE TABLE `rpc`.`cve` ( `id` VARCHAR(20) NOT NULL , `publish_date` DATE NULL DEFAULT NULL , `last_update` DATE NULL DEFAULT NULL , `description` TEXT NULL DEFAULT NULL , `base_score_v3` FLOAT NULL DEFAULT NULL , `temporal_score_v3` FLOAT NULL DEFAULT NULL , `exploitability_score_v3` FLOAT NULL DEFAULT NULL , `impact_score_v3` FLOAT NULL DEFAULT NULL , `base_score_v2` FLOAT NULL DEFAULT NULL , `temporal_score_v2` FLOAT NULL DEFAULT NULL , `exploitability_score_v2` FLOAT NULL DEFAULT NULL, `impact_score_v2` FLOAT NULL DEFAULT NULL , `attack_vector` ENUM('network','adjacent_network','local','physical') NULL DEFAULT NULL , `attack_complexity` ENUM('low','high') NULL DEFAULT NULL , `privileges_required` ENUM('none','low','high') NULL DEFAULT NULL , `user_interaction` ENUM('none','required') NULL DEFAULT NULL , `scope` ENUM('unchanged','changed') NULL DEFAULT NULL , `access_vector` ENUM('local','adjacent_network','network') NULL DEFAULT NULL , `access_complexity` ENUM('high','medium','low') NULL DEFAULT NULL , `authentication` ENUM('multiple','single','none') NULL DEFAULT NULL , `confidentiality_impact_v3` ENUM('none','low','high') NULL DEFAULT NULL , `integrity_impact_v3` ENUM('none','low','high') NULL DEFAULT NULL , `availability_impact_v3` ENUM('none','low','high') NULL DEFAULT NULL , `confidentiality_impact_v2` ENUM('none','partial','complete') NULL DEFAULT NULL , `integrity_impact_v2` ENUM('none','partial','complete') NULL DEFAULT NULL , `availability_impact_v2` ENUM('none','partial','complete') NULL DEFAULT NULL , `exploit_code_maturity` ENUM('not_defined','unproven_that_exploit_exists','proof_of_concept_code','functional_exploit_exists','high') NULL DEFAULT NULL , `remediation_level_v3` ENUM('not_defined','official_fix','temporary_fix','workaround','unavailable') NULL DEFAULT NULL , `report_confidence_v3` ENUM('not_defined','unknown','reasonable','confirmed') NULL DEFAULT NULL , `exploitability` ENUM('not_defined','unproven_that_exploit_exists','proof_of_concept_code','functional_exploit_exists','high') NULL DEFAULT NULL , `remediation_level_v2` ENUM('not_defined','official','temporary_fix','workaround','unavailable') NULL DEFAULT NULL , `report_confidence_v2` ENUM('not_defined','unconfirmed','uncorroborated','confirmed') NULL DEFAULT NULL , `gained_access` ENUM('none','user','admin','other') NULL DEFAULT NULL , `vector` VARCHAR(100) NULL DEFAULT NULL , `cwe_id` VARCHAR(30) NULL DEFAULT NULL , PRIMARY KEY (`id`(20)), FOREIGN KEY (`cwe_id`) REFERENCES cwe(`id`)) ENGINE = InnoDB;

create table vulnerability_type
(
	cve_id varchar(20) not null,
	vulnerability_type enum('dos', 'code_execution', 'overflow', 'memory_corruption', 'sql_injection', 'xss', 'directory_traversal', 'http_response_splitting', 'bypass_something', 'gain_information', 'gain_privileges', 'csrf', 'file_inclusion') not null,
	constraint vulnerability_type_pk
		primary key (cve_id, vulnerability_type),
	constraint cve_id_vulnerability_type_fk
		foreign key (cve_id) references cve (id)
);

create table product_type
(
	cve_id varchar(20) not null,
	product_type enum('application', 'os', 'hardware') not null,
	constraint product_type_pk
		primary key (cve_id, product_type),
	constraint cve_id_product_type_fk
		foreign key (cve_id) references cve (id)
);

create table os
(
	cwe_id varchar(30) not null,
	os enum('windows', 'mac', 'linux') not null,
	constraint os_pk
		primary key (cwe_id, os),
	constraint cwe_id_os_fk
		foreign key (cwe_id) references cwe (id)
);

create table technology
(
	cwe_id varchar(30) not null,
	technology enum('web_server', 'database_server') not null,
	constraint technology_pk
		primary key (cwe_id, technology),
	constraint cwe_id_technology_fk
		foreign key (cwe_id) references cwe (id)
);

create table paradigm
(
	cwe_id varchar(30) not null,
	paradigm enum('mobile', 'web_based', 'client_server', 'concurrent_systems_operating_on_shared_resources') not null,
	constraint paradigm_pk
		primary key (cwe_id, paradigm),
	constraint cwe_id_paradigm_fk
		foreign key (cwe_id) references cwe (id)
);

create table language_cwe
(
	cwe_id varchar(30) not null,
	language enum('python', 'java', 'javascript', 'csharp', 'php', 'c_cpp', 'r', 'objective-c', 'swift', 'matlab', 'typescript', 'ruby', 'kotlin', 'vba', 'go', 'scala', 'visual_basic', 'rust', 'perl', 'lua', 'haskell', 'delphi', 'julia', 'xml', 'sql', 'assembly') not null,
	constraint language_pk
		primary key (cwe_id, language),
	constraint cwe_id_language_fk
		foreign key (cwe_id) references cwe (id)
);

create table language_cve
(
	cve_id varchar(20) not null,
	language enum('python', 'java', 'javascript', 'csharp', 'php', 'c_cpp', 'r', 'objective-c', 'swift', 'matlab', 'typescript', 'ruby', 'kotlin', 'vba', 'go', 'scala', 'visual_basic', 'rust', 'perl', 'lua', 'haskell', 'delphi', 'julia') not null,
	constraint language_pk
		primary key (cve_id, language),
	constraint cve_id_language_fk
		foreign key (cve_id) references cve (id)
);

CREATE table cve_prob_by_time
(
	cve_id varchar(20) not null,
	`from` datetime not null,
	`to` datetime not null,
	attack_time_mu float not null,
	attack_time_sigma float not null,
	waiting_time_mu float not null,
	waiting_time_sigma float not null,
	constraint cve_id_fk
		foreign key (cve_id) references cve (id)
);
