--
-- +-------------------------------------------------------------------------------------------------------------------+
-- | Relational Data Model (SQLite) for MITRE ATT&CK™ Data                                                             |
-- +-------------------------------------------------------------------------------------------------------------------+
-- | AUTHOR : NADER SHALABI                                                                                            |
-- | www.cyber-distance.com                                                                                            |
-- +-------------------------------------------------------------------------------------------------------------------+
--

create table aliases
(
    fk_object_id VARCHAR,
    alias        VARCHAR
);

create table atomic_attack
(
    id                    VARCHAR,
    fk_attack_id          VARCHAR,
    fk_attack_external_id VARCHAR,
    display_name          VARCHAR
);

create table atomic_attack_test
(
    id                  VARCHAR,
    fk_atomic_attack_id VARCHAR,
    name                VARCHAR,
    description         VARCHAR,
    windows             VARCHAR,
    linux               VARCHAR,
    macos               VARCHAR,
    office_365          VARCHAR,
    azure_ad            VARCHAR,
    azure               VARCHAR,
    gcp                 VARCHAR,
    aws                 VARCHAR,
    saas                VARCHAR,
    android             VARCHAR,
    executor_name       VARCHAR,
    executor_command    VARCHAR
);

create table atomic_input_arguments
(
    id                       VARCHAR,
    fk_atomic_attack_test_id VARCHAR,
    name                     VARCHAR,
    description              VARCHAR,
    input_type               VARCHAR,
    default_value            VARCHAR
);

create table bundle
(
    id           VARCHAR,
    spec_version VARCHAR default '2.0'
);

create table emulation_plan
(
    id             VARCHAR,
    fk_bundle_id   VARCHAR,
    created_by_ref VARCHAR,
    name           VARCHAR,
    description    VARCHAR,
    created        VARCHAR,
    modified       VARCHAR,
    start_date     VARCHAR,
    end_date       VARCHAR,
    revoked        VARCHAR,
    marked_color   VARCHAR default "#c0dcc0"
);

create table emulation_plan_tags
(
    id                   VARCHAR,
    fk_emulation_plan_id VARCHAR,
    tag                  VARCHAR,
    tag_color            VARCHAR
);

create table external_references
(
    fk_object_id VARCHAR,
    url          VARCHAR,
    source_name  VARCHAR,
    external_id  VARCHAR,
    description  VARCHAR
);

create table goals
(
    fk_intrusion_set_id VARCHAR,
    goal                VARCHAR
);

create table granular_markings
(
    fk_object_id             VARCHAR,
    fk_marking_definition_id VARCHAR,
    selector                 VARCHAR
);

create table intrusion_set_secondary_motivations
(
    fk_intrusion_set_id  VARCHAR,
    secondary_motivation VARCHAR
);

create table kill_chain_phases
(
    fk_object_id    VARCHAR,
    kill_chain_name VARCHAR,
    phase_name      VARCHAR
);

create table labels
(
    fk_object_id VARCHAR,
    label        VARCHAR
);

create table marking_definition
(
    id                          VARCHAR,
    fk_bundle_id                VARCHAR,
    definition_type             VARCHAR,
    definition                  VARCHAR,
    created_by_ref              VARCHAR,
    created                     VARCHAR,
    x_mitre_attack_spec_version VARCHAR
);

create table object_marking_refs
(
    fk_object_id             VARCHAR,
    fk_marking_definition_id VARCHAR
);

create table platforms
(
    id            VARCHAR,
    platform_name VARCHAR
);

create table relationship
(
    id                          VARCHAR,
    fk_bundle_id                VARCHAR,
    relationship_type           VARCHAR,
    description                 VARCHAR,
    source_ref                  VARCHAR,
    source_ref_type             VARCHAR,
    target_ref                  VARCHAR,
    target_ref_type             VARCHAR,
    object_marking_refs         VARCHAR,
    created                     VARCHAR,
    created_by_ref              VARCHAR,
    modified                    VARCHAR,
    x_mitre_version             VARCHAR,
    x_mitre_modified_by_ref     VARCHAR,
    revoked                     VARCHAR,
    x_mitre_deprecated          VARCHAR,
    x_mitre_attack_spec_version VARCHAR
);

create table report_object_refs
(
    fk_report_id          VARCHAR,
    fk_object_id          VARCHAR,
    object_reference_type VARCHAR
);

create table sdos_object
(
    id                                                            VARCHAR,
    fk_bundle_id                                                  VARCHAR,
    created_by_ref                                                VARCHAR,
    created                                                       VARCHAR,
    modified                                                      VARCHAR,
    object_marking_refs                                           VARCHAR,
    revoked                                                       VARCHAR,
    name                                                          VARCHAR,
    description                                                   VARCHAR,
    type                                                          VARCHAR,
    first_seen                                                    VARCHAR,
    last_seen                                                     VARCHAR,
    objective                                                     VARCHAR,
    identity_class                                                VARCHAR,
    contact_information                                           VARCHAR,
    pattern                                                       VARCHAR,
    valid_from                                                    VARCHAR,
    valid_until                                                   VARCHAR,
    resource_level                                                VARCHAR,
    primary_motivation                                            VARCHAR,
    first_observed                                                VARCHAR,
    last_observed                                                 VARCHAR,
    number_observed                                               VARCHAR,
    published                                                     VARCHAR,
    sophistication                                                VARCHAR,
    tool_version                                                  VARCHAR,
    count                                                         VARCHAR,
    sighting_of_ref                                               VARCHAR,
    sighting_of_ref_type                                          VARCHAR,
    summary                                                       VARCHAR,
    x_mitre_platforms_windows                                     VARCHAR,
    x_mitre_platforms_network                                     VARCHAR,
    x_mitre_platforms_linux                                       VARCHAR,
    x_mitre_platforms_macOS                                       VARCHAR,
    x_mitre_platforms_android                                     VARCHAR,
    x_mitre_platforms_containers                                  VARCHAR,
    x_mitre_platforms_iaas                                        VARCHAR,
    x_mitre_platforms_ios                                         VARCHAR,
    x_mitre_platforms_field_controller_rtu_plc_ied                VARCHAR,
    x_mitre_platforms_engineering_workstation                     VARCHAR,
    x_mitre_platforms_office_365                                  VARCHAR,
    x_mitre_platforms_azure_ad                                    VARCHAR,
    x_mitre_platforms_pre                                         VARCHAR,
    x_mitre_platforms_saas                                        VARCHAR,
    x_mitre_platforms_google_workspace                            VARCHAR,
    x_mitre_platforms_safety_instrumented_system_protection_relay VARCHAR,
    x_mitre_platforms_none                                        VARCHAR,
    x_mitre_platforms_human_machine_interface                     VARCHAR,
    x_mitre_platforms_control_server                              VARCHAR,
    x_mitre_platforms_data_historian                              VARCHAR,
    x_mitre_platforms_input_output_server                         VARCHAR,
    x_mitre_system_requirements                                   VARCHAR,
    x_mitre_remote_support                                        VARCHAR,
    x_mitre_network_requirements                                  VARCHAR,
    x_mitre_detection                                             VARCHAR,
    x_mitre_version                                               VARCHAR,
    x_mitre_is_subtechnique                                       VARCHAR,
    x_mitre_first_seen_citation                                   VARCHAR,
    x_mitre_last_seen_citation                                    VARCHAR,
    x_mitre_deprecated                                            VARCHAR,
    x_mitre_attack_spec_version                                   VARCHAR,
    x_mitre_modified_by_ref                                       VARCHAR,
    x_mitre_data_source_ref                                       VARCHAR
);

create table sdos_object_platforms
(
    fk_platforms_id   VARCHAR,
    fk_sdos_object_id VARCHAR
);

create table search_database_config
(
    k not null
        primary key,
    v
)
    without rowid;

create table search_database_content
(
    id INTEGER
        primary key,
    c0,
    c1,
    c2,
    c3
);

create table search_database_data
(
    id    INTEGER
        primary key,
    block BLOB
);

create table search_database_docsize
(
    id INTEGER
        primary key,
    sz BLOB
);

create table search_database_idx
(
    segid not null,
    term  not null,
    pgno,
    primary key (segid, term)
)
    without rowid;

create table sectors
(
    fk_identity_id VARCHAR,
    sector         VARCHAR
);

create table testing_guideline
(
    id                   VARCHAR,
    fk_emulation_plan_id VARCHAR,
    name                 VARCHAR,
    description          VARCHAR,
    framework            VARCHAR,
    implementation       VARCHAR,
    result               VARCHAR,
    detected_ioc         VARCHAR,
    lessons_learned      VARCHAR,
    revoked              VARCHAR,
    test_completed       VARCHAR default "false",
    order_no             VARCHAR default "",
    marked_color         VARCHAR default "#a6caf0"
);

create table testing_guideline_tags
(
    id                      VARCHAR,
    fk_testing_guideline_id VARCHAR,
    tag                     VARCHAR,
    tag_color               VARCHAR
);

create table testing_guideline_technique
(
    id                      VARCHAR,
    fk_testing_guideline_id VARCHAR,
    fk_attack_id            VARCHAR,
    fk_attack_external_id   VARCHAR
);

create table testing_target
(
    id            VARCHAR,
    ip_v4_address VARCHAR,
    ip_v6_address VARCHAR,
    hostname      VARCHAR,
    tag           VARCHAR,
    owner         VARCHAR,
    type          VARCHAR
);

create table testing_target_guideline
(
    id                      VARCHAR,
    fk_target_id            VARCHAR,
    fk_testing_guideline_id VARCHAR
);

create table threat_actor_personal_motivations
(
    fk_threat_actor_id  VARCHAR,
    personal_motivation VARCHAR
);

create table threat_actor_secondary_motivations
(
    fk_threat_actor_id   VARCHAR,
    secondary_motivation VARCHAR
);

create table x_mitre_aliases
(
    fk_object_id  VARCHAR,
    x_mitre_alias VARCHAR
);

create table x_mitre_collection_layers
(
    fk_object_id VARCHAR,
    layer        VARCHAR
);

create table x_mitre_contributors
(
    fk_object_id        VARCHAR,
    x_mitre_contributor VARCHAR
);

create table x_mitre_data_sources
(
    fk_object_id        VARCHAR,
    x_mitre_data_source VARCHAR
);

create table x_mitre_defenses_bypassed
(
    fk_object_id             VARCHAR,
    x_mitre_defense_bypassed VARCHAR
);

create table x_mitre_domains
(
    fk_object_id   VARCHAR,
    x_mitre_domain VARCHAR
);

create table x_mitre_effective_permissions
(
    fk_object_id                 VARCHAR,
    x_mitre_effective_permission VARCHAR
);

create table x_mitre_permissions_required
(
    fk_object_id                VARCHAR,
    x_mitre_permission_required VARCHAR
);

create virtual table search_database using FTS5
(
    object_id,
    source_table,
    source_column,
    search_result
);

