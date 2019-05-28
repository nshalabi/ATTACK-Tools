--
-- +-------------------------------------------------------------------------------------------------------------------+
-- | Relational Data Model (SQLite) for MITRE ATT&CK™ Data                                                             |
-- +-------------------------------------------------------------------------------------------------------------------+
-- | AUTHOR : NADER SHALABI                                                                                            |
-- +-------------------------------------------------------------------------------------------------------------------+
--

create table aliases
(
	fk_object_id VARCHAR,
	alias VARCHAR
);

create table atomic_attack
(
	id VARCHAR,
	fk_attack_id VARCHAR,
	fk_attack_external_id VARCHAR,
	display_name VARCHAR
);

create table atomic_attack_test
(
	id VARCHAR,
	fk_atomic_attack_id VARCHAR,
	name VARCHAR,
	description VARCHAR,
	windows VARCHAR,
	linux VARCHAR,
	macos VARCHAR,
	executor_name VARCHAR,
	executor_command VARCHAR
);

create table atomic_input_arguments
(
	id VARCHAR,
	fk_atomic_attack_test_id VARCHAR,
	name VARCHAR,
	description VARCHAR,
	input_type VARCHAR,
	default_value VARCHAR
);

create table bundle
(
	id VARCHAR,
	spec_version VARCHAR default '2.0'
);

create table emulation_plan
(
	id VARCHAR,
	fk_bundle_id VARCHAR,
	created_by_ref VARCHAR,
	name VARCHAR,
	description VARCHAR,
	created VARCHAR,
	modified VARCHAR,
	start_date VARCHAR,
	end_date VARCHAR,
	revoked VARCHAR,
	marked_color VARCHAR default "#c0dcc0"
);

create table emulation_plan_tags
(
	id VARCHAR,
	fk_emulation_plan_id VARCHAR,
	tag VARCHAR,
	tag_color VARCHAR
);

create table external_references
(
	id VARCHAR,
	fk_object_id VARCHAR,
	url VARCHAR,
	source_name VARCHAR,
	external_id VARCHAR,
	description VARCHAR
);

create table goals
(
	fk_intrusion_set_id VARCHAR,
	goal VARCHAR
);

create table granular_markings
(
	fk_object_id VARCHAR,
	fk_marking_definition_id VARCHAR,
	selector VARCHAR
);

create table intrusion_set_secondary_motivations
(
	fk_intrusion_set_id VARCHAR,
	secondary_motivation VARCHAR
);

create table kill_chain_phases
(
	id VARCHAR,
	fk_object_id VARCHAR,
	kill_chain_name VARCHAR,
	phase_name VARCHAR
);

create table labels
(
	fk_object_id VARCHAR,
	label VARCHAR
);

create table marking_definition
(
	id VARCHAR,
	fk_bundle_id VARCHAR,
	fk_object_id VARCHAR,
	definition_type VARCHAR,
	definition VARCHAR,
	created_by_ref VARCHAR,
	created VARCHAR
);

create table object_marking_refs
(
	fk_object_id VARCHAR,
	fk_marking_definition_id VARCHAR
);

create table platforms
(
	id VARCHAR,
	platform_name VARCHAR
);

create table relationship
(
	id VARCHAR,
	fk_bundle_id VARCHAR,
	relationship_type VARCHAR,
	description VARCHAR,
	source_ref VARCHAR,
	source_ref_type VARCHAR,
	target_ref VARCHAR,
	target_ref_type VARCHAR
);

create table report_object_refs
(
	fk_report_id VARCHAR,
	fk_object_id VARCHAR,
	object_reference_type VARCHAR
);

create table sdos_object
(
	id VARCHAR,
	fk_bundle_id VARCHAR,
	created_by_ref VARCHAR,
	created VARCHAR,
	modified VARCHAR,
	revoked VARCHAR,
	name VARCHAR,
	description VARCHAR,
	type VARCHAR,
	first_seen VARCHAR,
	last_seen VARCHAR,
	objective VARCHAR,
	identity_class VARCHAR,
	contact_information VARCHAR,
	pattern VARCHAR,
	valid_from VARCHAR,
	valid_until VARCHAR,
	resource_level VARCHAR,
	primary_motivation VARCHAR,
	first_observed VARCHAR,
	last_observed VARCHAR,
	number_observed VARCHAR,
	published VARCHAR,
	sophistication VARCHAR,
	tool_version VARCHAR,
	count VARCHAR,
	sighting_of_ref VARCHAR,
	sighting_of_ref_type VARCHAR,
	summary VARCHAR,
	x_mitre_platforms_windows VARCHAR,
	x_mitre_platforms_macOS VARCHAR,
	x_mitre_platforms_linux VARCHAR,
	x_mitre_system_requirements VARCHAR,
	x_mitre_remote_support VARCHAR,
	x_mitre_network_requirements VARCHAR,
	x_mitre_detection VARCHAR
);

create table sdos_object_platforms
(
	fk_platforms_id VARCHAR,
	fk_sdos_object_id VARCHAR
);

create table sectors
(
	fk_identity_id VARCHAR,
	sector VARCHAR
);

create table testing_guideline
(
	id VARCHAR,
	fk_emulation_plan_id VARCHAR,
	name VARCHAR,
	description VARCHAR,
	framework VARCHAR,
	implementation VARCHAR,
	result VARCHAR,
	detected_ioc VARCHAR,
	lessons_learned VARCHAR,
	revoked VARCHAR,
	test_completed VARCHAR default "false",
	order_no VARCHAR default "",
	marked_color VARCHAR default "#a6caf0"
);

create table testing_guideline_tags
(
	id VARCHAR,
	fk_testing_guideline_id VARCHAR,
	tag VARCHAR,
	tag_color VARCHAR
);

create table testing_guideline_technique
(
	id VARCHAR,
	fk_testing_guideline_id VARCHAR,
	fk_attack_id VARCHAR,
	fk_attack_external_id VARCHAR
);

create table testing_target
(
	id VARCHAR,
	ip_v4_address VARCHAR,
	ip_v6_address VARCHAR,
	hostname VARCHAR,
	tag VARCHAR,
	owner VARCHAR,
	type VARCHAR
);

create table testing_target_guideline
(
	id VARCHAR,
	fk_target_id VARCHAR,
	fk_testing_guideline_id VARCHAR
);

create table threat_actor_personal_motivations
(
	fk_threat_actor_id VARCHAR,
	personal_motivation VARCHAR
);

create table threat_actor_secondary_motivations
(
	fk_threat_actor_id VARCHAR,
	secondary_motivation VARCHAR
);

create table x_mitre_aliases
(
	id VARCHAR,
	fk_object_id VARCHAR,
	x_mitre_alias VARCHAR
);

create table x_mitre_contributors
(
	id VARCHAR,
	fk_object_id VARCHAR,
	x_mitre_contributor VARCHAR
);

create table x_mitre_data_sources
(
	id VARCHAR,
	fk_object_id VARCHAR,
	x_mitre_data_source VARCHAR
);

create table x_mitre_defenses_bypassed
(
	id VARCHAR,
	fk_object_id VARCHAR,
	x_mitre_defense_bypassed VARCHAR
);

create table x_mitre_effective_permissions
(
	id VARCHAR,
	fk_object_id VARCHAR,
	x_mitre_effective_permission VARCHAR
);

create table x_mitre_permissions_required
(
	id VARCHAR,
	fk_object_id VARCHAR,
	x_mitre_permission_required VARCHAR
);