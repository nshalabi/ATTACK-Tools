--
-- +-------------------------------------------------------------------------------------------------------------------+
-- | STIX™ 2.0 Relational Data Model (SQLite) with MITRE ATT&CK™ Data                                                  |
-- +-------------------------------------------------------------------------------------------------------------------+
-- | AUTHOR : NADER SHALABI                                                                                            |
-- +-------------------------------------------------------------------------------------------------------------------+
--

BEGIN TRANSACTION;

DROP TABLE IF EXISTS bundle;
CREATE TABLE bundle(
   id           VARCHAR
  ,spec_version VARCHAR DEFAULT '2.0'
);

--
-- SDOS - STIX 2.0 Domain Objects shared attributes and common objects
-- with one to many relationship with their parent object
--

DROP TABLE IF EXISTS labels;
CREATE TABLE labels(
   fk_object_id VARCHAR -- sdos object reference
  ,label        VARCHAR
  -- malware labels: "adware", "backdoor", "bot", "ddos", "dropper", "exploit-kit", "keylogger", "ransomware",
  --                 "remote-access-trojan", "resource-exploitation", "rogue-antivirus", "rootkit", "screen-capture",
  --                 "spyware", "trojan", "virus", "worm"

  -- indicator labels: "anomalous-activity", "anonymization", "benign", "compromised", "malicious-activity",
  --                   "attribution"
  -- report labels: "threat-report", "attack-pattern", "campaign", "identity", "indicator", "malware", "observed-data",
  --                "threat-actor", "tool", "vulnerability"
  -- threat_actor labels: "activist", "competitor", "crime-syndicate", "criminal", "hacker", "insider-accidental",
  --                       "insider-disgruntled", "nation-state", "sensationalist", "spy", "terrorist"
  -- tool labels: "denial-of-service", "exploitation", "information-gathering", "network-capture",
  --              "credential-exploitation", "remote-access", "vulnerability-scanning"
);

DROP TABLE IF EXISTS external_references;
CREATE TABLE external_references(
   fk_object_id VARCHAR -- sdos object reference, marking_definition, emulation_plan, testing_guideline
  ,url          VARCHAR
  ,source_name  VARCHAR
  ,external_id  VARCHAR
  ,description  VARCHAR
);

DROP TABLE IF EXISTS object_marking_refs;
CREATE TABLE object_marking_refs(
   fk_object_id             VARCHAR -- sdos object reference, marking_definition
  ,fk_marking_definition_id VARCHAR -- refers to marking_definition
);

DROP TABLE IF EXISTS granular_markings;
CREATE TABLE granular_markings(
   fk_object_id             VARCHAR -- sdos object reference, marking_definition
  ,fk_marking_definition_id VARCHAR -- refers to marking_definition
  ,selector                 VARCHAR
);

DROP TABLE IF EXISTS hashes;
CREATE TABLE hashes(
   fk_object_id VARCHAR -- refers to external_references, artifact, alternate_data_streams,
                        -- windows_pe_optional_header_type, windows_pe_section, file, x509_certificate
  ,hash         VARCHAR
  ,type         VARCHAR
);

DROP TABLE IF EXISTS kill_chain_phases;
CREATE TABLE kill_chain_phases(
   fk_object_id    VARCHAR -- can refer to attack_pattern, indicator, malware, tool
  ,kill_chain_name VARCHAR
  ,phase_name      VARCHAR
);

DROP TABLE IF EXISTS marking_definition;
CREATE TABLE marking_definition(
   fk_bundle_id    VARCHAR -- refers to bundle
  ,fk_object_id    VARCHAR -- sdos object reference
  ,id              VARCHAR
  ,definition_type VARCHAR --"statement", "tlp"
  ,definition      VARCHAR -- statement text or tlp value ("white", "green", "amber", "red", for more information check https://www.us-cert.gov/tlp)
  ,created_by_ref  VARCHAR -- foreign key to identity
  ,created         VARCHAR
);

DROP TABLE IF EXISTS aliases;
CREATE TABLE aliases(
   fk_object_id VARCHAR -- can refer to campaign, intrusion-set, threat-actor
  ,alias        VARCHAR
);

DROP TABLE IF EXISTS goals;
CREATE TABLE goals(
   fk_intrusion_set_id VARCHAR -- refers to intrusion_set
  ,goal                VARCHAR
);

DROP TABLE IF EXISTS intrusion_set_secondary_motivations;
CREATE TABLE intrusion_set_secondary_motivations(
   fk_intrusion_set_id  VARCHAR -- refers to intrusion_set
  ,secondary_motivation VARCHAR -- "accidental", "coercion", "dominance", "ideology", "notoriety", "organizational-gain",
                                -- "personal-gain", "personal-satisfaction", "revenge", "unpredictable"
);

DROP TABLE IF EXISTS threat_actor_secondary_motivations;
CREATE TABLE threat_actor_secondary_motivations(
   fk_threat_actor_id   VARCHAR -- refers to threat_actor
  ,secondary_motivation VARCHAR -- "accidental", "coercion", "dominance", "ideology", "notoriety", "organizational-gain",
                                -- "personal-gain", "personal-satisfaction", "revenge", "unpredictable"
);

DROP TABLE IF EXISTS threat_actor_personal_motivations;
CREATE TABLE threat_actor_personal_motivations(
   fk_threat_actor_id  VARCHAR -- refers to threat_actor
  ,personal_motivation VARCHAR -- "accidental", "coercion", "dominance", "ideology", "notoriety", "organizational-gain",
                               -- "personal-gain", "personal-satisfaction", "revenge", "unpredictable"
);

DROP TABLE IF EXISTS sectors;
CREATE TABLE sectors(
   fk_identity_id VARCHAR -- refers to identity
  ,sector         VARCHAR -- "agriculture", "aerospace", "automotive", "communications", "construction", "defence",
                          -- "education", "energy", "engineering", "entertainment", "financial-services",
                          -- "government-national", "government-regional", "government-local",
                          -- "government-public-services", "healthcare", "hospitality-leisure", "infrastructure",
                          -- "insurance", "manufacturing", "mining", "non-profit", "pharmaceuticals", "retail",
                          -- "technology", "telecommunications", "transportation", "utilities"
);

--
-- observables
--

DROP TABLE IF EXISTS artifact;
CREATE TABLE artifact(
   pk_id               VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id VARCHAR -- refers to observed_data
  ,mime_type           VARCHAR -- "application", "audio", "font", "image", "message", "model", "multipart", "text", "video" or custom defined
  ,payload_bin         VARCHAR
  ,url                 VARCHAR
);

DROP TABLE IF EXISTS autonomous_system;
CREATE TABLE autonomous_system(
   pk_id               VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id VARCHAR -- refers to observed_data
  ,number              VARCHAR
  ,name                VARCHAR
  ,rir                 VARCHAR
);

DROP TABLE IF EXISTS directory_contains_refs;
CREATE TABLE directory_contains_refs(
   fk_directory_id           VARCHAR -- refers to directory
  ,referenced_obsevable_type VARCHAR -- type of referenced observable : directory, file
  ,fk_observable_id          VARCHAR -- refers to directory, file
);

DROP TABLE IF EXISTS directory;
CREATE TABLE directory(
   pk_id               VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id VARCHAR -- refers to observed_data
  ,path                VARCHAR
  ,path_enc            VARCHAR
  ,created             VARCHAR
  ,modified            VARCHAR
  ,accessed            VARCHAR
  -- any sub files or folders are referenced using directory_contains_refs table
);

DROP TABLE IF EXISTS domain_name_resolves_to_refs;
CREATE TABLE domain_name_resolves_to_refs(
   fk_domain_name_id         VARCHAR -- refers to domain_name
  ,referenced_obsevable_type VARCHAR -- type of referenced observable : domain_name, ipv4_addr, ipv6_addr
  ,fk_observable_id          VARCHAR -- refers to domain_name, ipv4_addr, ipv6_addr
);

DROP TABLE IF EXISTS domain_name;
CREATE TABLE domain_name(
   pk_id               VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id VARCHAR -- refers to observed_data
  ,value               VARCHAR
  -- any references to one or more IP addresses or domain names that the domain name resolves to are referenced using domain_name_resolves_to_refs table
);

DROP TABLE IF EXISTS email_addr;
CREATE TABLE email_addr(
   pk_id               VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id VARCHAR -- refers to observed_data
  ,value               VARCHAR
  ,display_name        VARCHAR
  ,belongs_to_ref      VARCHAR -- refers to user_account
);

DROP TABLE IF EXISTS to_refs;
CREATE TABLE to_refs(
   fk_email_message VARCHAR -- refers to email_message
  ,to_ref           VARCHAR
);

DROP TABLE IF EXISTS cc_refs;
CREATE TABLE cc_refs(
   fk_email_message VARCHAR -- refers to email_message
  ,cc_ref           VARCHAR
);

DROP TABLE IF EXISTS bcc_refs;
CREATE TABLE bcc_refs(
   fk_email_message VARCHAR -- refers to email_message
  ,bcc_ref          VARCHAR
);

DROP TABLE IF EXISTS received_lines;
CREATE TABLE received_lines(
   fk_email_message VARCHAR -- refers to email_message
  ,line             VARCHAR
);

DROP TABLE IF EXISTS email_additional_header_fields;
CREATE TABLE email_additional_header_fields(
   pk_id            VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_email_message VARCHAR -- refers to email_message
  ,header           VARCHAR -- any additional header except for "date", "received_lines", "content_type", "from_ref", "sender_ref", "to_refs", "cc_refs", "bcc_refs", "subject"
);

DROP TABLE IF EXISTS email_additional_header_field_values;
CREATE TABLE email_additional_header_field_values (
   fk_email_additional_header_fields VARCHAR -- refers to email_additional_header_fields
  ,value                             VARCHAR
);

DROP TABLE IF EXISTS body_multipart;
CREATE TABLE body_multipart(
   fk_email_message    VARCHAR -- refers to email_message
  ,body                VARCHAR
  ,body_raw_ref        VARCHAR -- refers to artifact
  ,content_type        VARCHAR
  ,content_disposition VARCHAR
);

DROP TABLE IF EXISTS email_message;
CREATE TABLE email_message(
   pk_id               VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id VARCHAR -- refers to observed_data
  ,date                VARCHAR
  ,content_type        VARCHAR
  ,from_ref            VARCHAR
  ,sender_ref          VARCHAR
  ,subject             VARCHAR
  ,raw_email_ref       VARCHAR -- refers to artifact
  ,is_multipart        VARCHAR -- "true", "false"
  ,body                VARCHAR -- if is_multipart is false, this field is used, else, a reference to body_multipart holds the contents of the MIME part
);

DROP TABLE IF EXISTS alternate_data_streams;
CREATE TABLE alternate_data_streams(
   fk_ntfs_ext_id VARCHAR -- refers to ntfs_ext
  ,name           VARCHAR
  ,size           VARCHAR
);

DROP TABLE IF EXISTS ntfs_ext;
CREATE TABLE ntfs_ext(
   pk_id      VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_file_id VARCHAR -- refers to file
  ,sid        VARCHAR
);

DROP TABLE IF EXISTS exif_tags;
CREATE TABLE exif_tags(
   fk_raster_image_ext_id VARCHAR -- refers to raster_image_ext
  ,exif_tag               VARCHAR
  ,value                  VARCHAR
);

DROP TABLE IF EXISTS raster_image_ext;
CREATE TABLE raster_image_ext(
   pk_id                       VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_file_id                  VARCHAR -- refers to file
  ,image_height                VARCHAR
  ,image_width                 VARCHAR
  ,bits_per_pixel              VARCHAR
  ,image_compression_algorithm VARCHAR
);

DROP TABLE IF EXISTS document_info_dict;
CREATE TABLE document_info_dict(
   fk_pdf_ext_id VARCHAR -- refers to pdf_ext
  ,did_key       VARCHAR
  ,did_value     VARCHAR
);

DROP TABLE IF EXISTS pdf_ext;
CREATE TABLE pdf_ext(
   pk_id        VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_file_id   VARCHAR -- refers to file
  ,version      VARCHAR
  ,is_optimized VARCHAR -- "true", "false"
  ,pdfid0       VARCHAR
  ,pdfid1       VARCHAR
);

DROP TABLE IF EXISTS archive_ext_contains_refs;
CREATE TABLE archive_ext_contains_refs(
   fk_archive_ext_id VARCHAR -- refers to archive_ext
  ,fk_file_id        VARCHAR -- refers to file
);

DROP TABLE IF EXISTS archive_ext;
CREATE TABLE archive_ext(
   pk_id      VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_file_id VARCHAR -- refers to file
  ,version    VARCHAR
  ,comment    VARCHAR
);

DROP TABLE IF EXISTS windows_pe_optional_header_type;
CREATE TABLE windows_pe_optional_header_type(
   fk_windows_pebinary_ext_id VARCHAR -- refers to windows_pebinary_ext
                                      --  this is a 1 to 1 relationship with windows_pebinary_ext
  ,magic_hex                  VARCHAR
  ,major_linker_version       VARCHAR
  ,minor_linker_version       VARCHAR
  ,size_of_code               VARCHAR
  ,size_of_initialized_data   VARCHAR
  ,size_of_uninitialized_data VARCHAR
  ,address_of_entry_point     VARCHAR
  ,base_of_code               VARCHAR
  ,base_of_data               VARCHAR
  ,image_base                 VARCHAR
  ,section_alignment          VARCHAR
  ,file_alignment             VARCHAR
  ,major_os_version           VARCHAR
  ,minor_os_version           VARCHAR
  ,major_image_version        VARCHAR
  ,minor_image_version        VARCHAR
  ,major_subsystem_version    VARCHAR
  ,minor_subsystem_version    VARCHAR
  ,win32_version_value_hex    VARCHAR
  ,size_of_image              VARCHAR
  ,size_of_headers            VARCHAR
  ,checksum_hex               VARCHAR
  ,subsystem_hex              VARCHAR
  ,dll_characteristics_hex    VARCHAR
  ,size_of_stack_reserve      VARCHAR
  ,size_of_stack_commit       VARCHAR
  ,size_of_heap_reserve       VARCHAR
  ,size_of_heap_commit        VARCHAR
  ,loader_flags_hex           VARCHAR
  ,number_of_rva_and_sizes    VARCHAR
);

DROP TABLE IF EXISTS windows_pe_section;
CREATE TABLE windows_pe_section(
   fk_windows_pebinary_ext_id VARCHAR -- refers to windows_pebinary_ext
  ,name                       VARCHAR
  ,size                       VARCHAR
  ,entropy                    VARCHAR
);

DROP TABLE IF EXISTS windows_pebinary_ext;
CREATE TABLE windows_pebinary_ext(
   pk_id                       VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_file_id                  VARCHAR -- refers to file
  ,pe_type                     VARCHAR -- "exe", "dll", "sys"
  ,imphash                     VARCHAR
  ,machine_hex                 VARCHAR
  ,number_of_sections          VARCHAR
  ,time_date_stamp             VARCHAR
  ,pointer_to_symbol_table_hex VARCHAR
  ,number_of_symbols           VARCHAR
  ,size_of_optional_header     VARCHAR
  ,characteristics_hex         VARCHAR
  ,file_header_hashes          VARCHAR
  ,optional_header             VARCHAR
);

DROP TABLE IF EXISTS file_contains_refs;
CREATE TABLE file_contains_refs(
   fk_file_id                VARCHAR -- refers to directory
  ,referenced_obsevable_type VARCHAR -- type of referenced observable : artifact, autonomous_system, directory,
                                     -- domain_name, email_addr, email_message, file, ipv4_addr, ipv6_addr,
                                     -- mac_addr, mutex, network_traffic, process, software, url, user_account,
                                     -- windows_registry_key, x509_certificate
  ,fk_observable_id          VARCHAR -- refers to any observable object
);

DROP TABLE IF EXISTS file;
CREATE TABLE file(
   pk_id                VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id  VARCHAR -- refers to observed_data
  ,size                 VARCHAR
  ,name                 VARCHAR
  ,name_enc             VARCHAR
  ,magic_number_hex     VARCHAR
  ,mime_type            VARCHAR
  ,created              VARCHAR
  ,modified             VARCHAR
  ,accessed             VARCHAR
  ,parent_directory_ref VARCHAR -- refers to directory (parent directory)
  ,content_ref          VARCHAR -- refers to artifact
  ,is_encrypted         VARCHAR -- "true", "false"
  ,encryption_algorithm VARCHAR -- "AES128-ECB", "AES128-CBC", "AES128-CFB", "AES128-COFB", "AES128-CTR", "AES128-XTS",
                                -- "AES128-GCM", "Salsa20", "Salsa8B", "ChaCha20-Poly1305", "ChaCha20", "DES-CBC",
                                -- "3DES-CBC", "DES-EBC", "3DES-EBC", "CAST128-CBC", "CAST256-CBC", "RSA", "DSA"
  ,decryption_key       VARCHAR
);

DROP TABLE IF EXISTS ipv4_addr_resolves_to_refs;
CREATE TABLE ipv4_addr_resolves_to_refs(
   fk_ipv4_addr_id VARCHAR -- refers to ipv4_addr
  ,fk_mac_addr_id  VARCHAR -- refers to any mac_addr object
);

DROP TABLE IF EXISTS ipv4_addr_belongs_to_refs;
CREATE TABLE ipv4_addr_belongs_to_refs(
   fk_ipv4_addr_id         VARCHAR -- refers to ipv4_addr
  ,fk_autonomous_system_id VARCHAR -- refers to any autonomous_system object
);

DROP TABLE IF EXISTS ipv4_addr;
CREATE TABLE ipv4_addr(
   pk_id               VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id VARCHAR -- refers to observed_data
  ,value               VARCHAR
);

DROP TABLE IF EXISTS ipv6_addr_resolves_to_refs;
CREATE TABLE ipv6_addr_resolves_to_refs(
   fk_ipv6_addr_id VARCHAR -- refers to ipv6_addr
  ,fk_mac_addr_id  VARCHAR -- refers to any mac_addr object
);

DROP TABLE IF EXISTS ipv6_addr_belongs_to_refs;
CREATE TABLE ipv6_addr_belongs_to_refs(
   fk_ipv6_addr_id         VARCHAR -- refers to ipv6_addr
  ,fk_autonomous_system_id VARCHAR -- refers to any autonomous_system object
);

DROP TABLE IF EXISTS ipv6_addr;
CREATE TABLE ipv6_addr(
   pk_id               VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id VARCHAR -- refers to observed_data
  ,value               VARCHAR
);

DROP TABLE IF EXISTS mac_addr;
CREATE TABLE mac_addr(
   pk_id               VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id VARCHAR -- refers to observed_data
  ,value               VARCHAR
);

DROP TABLE IF EXISTS mutex;
CREATE TABLE mutex(
   pk_id               VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id VARCHAR -- refers to observed_data
  ,value               VARCHAR
);

DROP TABLE IF EXISTS network_traffic_encapsulates_refs;
CREATE TABLE network_traffic_encapsulates_refs(
   fk_network_traffic_id  VARCHAR -- refers to network_traffic
  ,fk_encapsulated_ref_id VARCHAR -- refers to network_traffic
);

DROP TABLE IF EXISTS ipfix;
CREATE TABLE ipfix(
   fk_network_traffic_id VARCHAR -- refers to network_traffic
  ,ipfix_key             VARCHAR
  ,ipfix_value           VARCHAR
);

DROP TABLE IF EXISTS protocols;
CREATE TABLE protocols(
   fk_network_traffic_id VARCHAR -- refers to network_traffic
  ,encapsulation_index   VARCHAR -- used to arrange protocols from outer to inner in terms of packet encapsulation, that
                                 -- is, the protocols in the outer level of the packet, such as IP, must be listed first,
                                 -- for example, starts with encapsulation_index 0, then 1, 2, etc.
  ,protocol              VARCHAR -- service names defined in the Service Name column of the IANA Service Name and Port
                                 -- Number Registry
                                 -- [http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml]
);

DROP TABLE IF EXISTS request_header;
CREATE TABLE request_header(
   fk_http_request_ext_id VARCHAR -- refers to http_request_ext
  ,http_header_name       VARCHAR
  ,http_header__value     VARCHAR
);

DROP TABLE IF EXISTS http_request_ext;
CREATE TABLE http_request_ext(
   pk_id                 VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_network_traffic_id VARCHAR -- refers to network_traffic
  ,request_method        VARCHAR
  ,request_value         VARCHAR
  ,request_version       VARCHAR
  ,message_body_data_ref VARCHAR -- refers to artifact
);

DROP TABLE IF EXISTS icmp_ext;
CREATE TABLE icmp_ext(
   fk_network_traffic_id VARCHAR -- refers to network_traffic
  ,icmp_type_hex         VARCHAR
  ,icmp_code_hex         VARCHAR
);

DROP TABLE IF EXISTS socket_options;
CREATE TABLE socket_options( -- changed the original JSON name "options" to a more descriptive name "socket_options"
   fk_socket_ext_id VARCHAR -- refers to socket_ext
  ,icmp_type_hex    VARCHAR
  ,icmp_code_hex    VARCHAR
);

DROP TABLE IF EXISTS socket_ext;
CREATE TABLE socket_ext(
   fk_network_traffic_id VARCHAR -- refers to network_traffic
  ,src_flags_hex         VARCHAR
  ,dst_flags_hex         VARCHAR
);

DROP TABLE IF EXISTS tcp_ext;
CREATE TABLE tcp_ext(
   pk_id                 VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_network_traffic_id VARCHAR -- refers to network_traffic
  ,address_family        VARCHAR -- "AF_UNSPEC", "AF_INET", "AF_IPX", "AF_APPLETALK", "AF_NETBIOS", "AF_INET6", "AF_IRDA",
                                 -- "AF_BTH"
  ,is_blocking           VARCHAR -- "true", "false"
  ,protocol_family       VARCHAR -- "PF_INET", "PF_AX25", "PF_IPX", "PF_INET6", "PF_APPLETALK", "PF_NETROM", "PF_BRIDGE",
                                 -- "PF_ATMPVC", "PF_X25", "PF_ROSE", "PF_DECNET", "PF_NETBEUI", "PF_SECURITY", "PF_KEY",
                                 -- "PF_NETLINK", "PF_ROUTE", "PF_PACKET", "PF_ASH", "PF_ECONET", "PF_ATMSVC", "PF_SNA",
                                 -- "PF_IRDA", "PF_PPPOX", "PF_WANPIPE", "PF_BLUETOOTH"
  ,socket_type           VARCHAR -- "SOCK_STREAM", "SOCK_DGRAM", "SOCK_RAW", "SOCK_RDM", "SOCK_SEQPACKET"
  ,socket_descriptor     VARCHAR
  ,socket_handle         VARCHAR
);

DROP TABLE IF EXISTS network_traffic;
CREATE TABLE network_traffic(
   pk_id               VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id VARCHAR -- refers to observed_data
  ,is_active           VARCHAR -- "true", "false"
  ,start_time          VARCHAR -- added _time to the original JSON field name
  ,end_time            VARCHAR -- added _time to the original JSON field name
  ,src_ref_type        VARCHAR -- "ipv4_addr", "ipv6_addr", "mac_addr", "domain_name"
  ,src_ref             VARCHAR -- refers to ipv4_addr, ipv6_addr, mac_addr, domain_name
  ,dst_ref_type        VARCHAR -- "ipv4_addr", "ipv6_addr", "mac_addr", "domain_name"
  ,dst_ref             VARCHAR -- refers to ipv4_addr, ipv6_addr, mac_addr, domain_name
  ,src_port            VARCHAR -- "0" .. "65535"
  ,dst_port            VARCHAR -- "0" .. "65535"
  ,src_byte_count      VARCHAR
  ,dst_byte_count      VARCHAR
  ,src_packets         VARCHAR
  ,dst_packets         VARCHAR
  ,src_payload_ref     VARCHAR -- refers to artifact
  ,dst_payload_ref     VARCHAR -- refers to artifact
  ,encapsulated_by_ref VARCHAR -- refers to network_traffic
                               -- might be redundant in a relational model (circular reference due to network_traffic_encapsulates_refs)
);

DROP TABLE IF EXISTS process_arguments;
CREATE TABLE process_arguments( -- changed the original JSON name "arguments" to a more descriptive name "process_arguments"
   fk_process_id VARCHAR -- refers to process
  ,argument      VARCHAR
);

DROP TABLE IF EXISTS environment_variables;
CREATE TABLE environment_variables(
   fk_process_id              VARCHAR -- refers to process
  ,environment_variable_name  VARCHAR
  ,environment_variable_value VARCHAR
);

DROP TABLE IF EXISTS process_opened_connection_refs;
CREATE TABLE process_opened_connection_refs(
   fk_process_id VARCHAR -- refers to process
  ,connction_ref VARCHAR -- refers to network_traffic
);

DROP TABLE IF EXISTS process_child_refs;
CREATE TABLE process_child_refs(
   fk_process_id VARCHAR -- refers to process (parent)
  ,child_ref     VARCHAR -- refers to process (child)
);

DROP TABLE IF EXISTS startup_info;
CREATE TABLE startup_info( -- this is a 1 to 1 relation with windows_process_ext, it can be merged
   fk_windows_process_ext_id VARCHAR -- refers to windows_process_ext
  ,lpDesktop                 VARCHAR
  ,lpTitle                   VARCHAR
  ,dwFillAttribute           VARCHAR
  ,dwFlags                   VARCHAR
  ,wShowWindow               VARCHAR
  ,hStdInput                 VARCHAR
  ,hStdOutput                VARCHAR
  ,hStdError                 VARCHAR
  ,lpReserved                VARCHAR
  ,lpReserved2               VARCHAR
  ,cb                        VARCHAR
  ,dwX                       VARCHAR
  ,dwY                       VARCHAR
  ,dwXSize                   VARCHAR
  ,dwYSize                   VARCHAR
  ,dwXCountChars             VARCHAR
  ,dwYCountChars             VARCHAR
);

DROP TABLE IF EXISTS windows_process_ext;
CREATE TABLE windows_process_ext(
   pk_id         VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_process_id VARCHAR -- refers to process
  ,aslr_enabled  VARCHAR -- "true", "false"
  ,dep_enabled   VARCHAR -- "true", "false"
  ,priority      VARCHAR
  ,owner_sid     VARCHAR
  ,window_title  VARCHAR
);

DROP TABLE IF EXISTS service_dll_refs;
CREATE TABLE service_dll_refs(
   fk_windows_service_ext_id VARCHAR -- refers to windows_service_ext
   ,dll_ref                  VARCHAR -- refers to file
);

DROP TABLE IF EXISTS windows_service_descriptions;
CREATE TABLE windows_service_descriptions( -- changed the original JSON name "descriptions" to a more descriptive name "windows_service_descriptions"
   fk_windows_service_ext_id VARCHAR -- refers to windows_service_ext
  ,dll_ref                   VARCHAR -- refers to file
);

DROP TABLE IF EXISTS windows_service_ext;
CREATE TABLE windows_service_ext(
   pk_id          VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_process_id  VARCHAR -- refers to process
  ,service_name   VARCHAR
  ,display_name   VARCHAR
  ,group_name     VARCHAR
  ,start_type     VARCHAR -- "SERVICE_AUTO_START", "SERVICE_BOOT_START", "SERVICE_DEMAND_START", "SERVICE_DISABLED",
                          -- "SERVICE_SYSTEM_ALERT"
  ,service_type   VARCHAR -- "SERVICE_KERNEL_DRIVER", "SERVICE_FILE_SYSTEM_DRIVER", "SERVICE_WIN32_OWN_PROCESS",
                          -- "SERVICE_WIN32_SHARE_PROCESS"
  ,service_status VARCHAR -- "SERVICE_CONTINUE_PENDING", "SERVICE_PAUSE_PENDING", "SERVICE_PAUSED", "SERVICE_RUNNING",
                          -- "SERVICE_START_PENDING", "SERVICE_STOP_PENDING", "SERVICE_STOPPED"
);

DROP TABLE IF EXISTS process;
CREATE TABLE process(
   pk_id               VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id VARCHAR -- refers to observed_data
  ,is_hidden           VARCHAR -- "true", "false"
  ,pid                 VARCHAR
  ,name                VARCHAR
  ,created             VARCHAR
  ,cwd                 VARCHAR
  ,command_line        VARCHAR
  ,creator_user_ref    VARCHAR -- refers to user_account
  ,binary_ref          VARCHAR -- refers to file
  ,parent_ref          VARCHAR -- refers to process
);

DROP TABLE IF EXISTS software_languages;
CREATE TABLE software_languages( -- changed the original JSON name "languages" to a more descriptive name "software_languages"
   fk_software_id VARCHAR -- refers to software
  ,language       VARCHAR -- must be an ISO 639-2 language code [http://www.iso.org/iso/catalogue_detail?csnumber=4767]
);

DROP TABLE IF EXISTS software;
CREATE TABLE software(
   pk_id               VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id VARCHAR -- refers to observed_data
  ,name                VARCHAR
  ,cpe                 VARCHAR -- if available. The value for this property MUST be a CPE v2.3 entry from the official
                               -- NVD CPE Dictionary [https://nvd.nist.gov/cpe.cfm]
  ,vendor              VARCHAR
  ,version             VARCHAR
);

DROP TABLE IF EXISTS url;
CREATE TABLE url(
   pk_id               VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id VARCHAR -- refers to observed_data
  ,value               VARCHAR
);

DROP TABLE IF EXISTS unix_account_groups;
CREATE TABLE unix_account_groups( -- changed the original JSON name "groups" to a more descriptive name "unix_account_groups"
   fk_unix_account_ext_id  VARCHAR -- refers to unix_account_ext
  ,group_name              VARCHAR
);

DROP TABLE IF EXISTS unix_account_ext;
CREATE TABLE unix_account_ext( -- this is a 1 to 1 relation with user_account, it can be merged
   pk_id              VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_user_account_id VARCHAR -- refers to user_account
  ,gid                VARCHAR
  ,home_dir           VARCHAR
  ,shell              VARCHAR
);

DROP TABLE IF EXISTS user_account;
CREATE TABLE user_account(
   pk_id               VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id VARCHAR -- refers to observed_data
  ,user_id             VARCHAR
  ,account_login       VARCHAR
  ,account_type        VARCHAR -- "unix", "windows local", "windows domain", "ldap", "tacacs", "radius", "nis", "openid",
                               -- "facebook", "skype", "twitter", "kavi"
  ,display_name        VARCHAR
  ,is_service_account  VARCHAR -- "true", "false"
  ,is_privileged       VARCHAR -- "true", "false"
  ,can_escalate_privs  VARCHAR -- "true", "false"
  ,is_disabled         VARCHAR -- "true", "false"
  ,account_created     VARCHAR
  ,account_expires     VARCHAR
  ,account_first_login VARCHAR
  ,account_last_login  VARCHAR
);

DROP TABLE IF EXISTS windows_registry_value;
CREATE TABLE windows_registry_value(
   fk_windows_registry_key_id VARCHAR -- refers to windows_registry_key
  ,name                       VARCHAR
  ,data                       VARCHAR
  ,data_type                  VARCHAR -- "REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD",
                                      -- "REG_DWORD_BIG_ENDIAN", "REG_LINK", "REG_MULTI_SZ", "REG_RESOURCE_LIST",
                                      -- "REG_FULL_RESOURCE_DESCRIPTION", "REG_RESOURCE_REQUIREMENTS_LIST", "REG_QWORD",
                                      -- "REG_INVALID_TYPE"
);

DROP TABLE IF EXISTS windows_registry_key;
CREATE TABLE windows_registry_key(
   pk_id               VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id VARCHAR -- refers to observed_data
  ,key                 VARCHAR
  ,hive                VARCHAR -- not available in teh original STIX 2.0, added for easier reference (better performance
                               -- than Regex), however, the key should follow the STIX 2.0 rule "Specifies the full
                               -- registry key including the hive", the following are the potential values assigned:
                               -- "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKEY_CLASSES_ROOT", "HKEY_CURRENT_CONFIG",
                               -- "HKEY_PERFORMANCE_DATA", "HKEY_USERS", "HKEY_DYN_DATA"
  ,modified            VARCHAR
  ,creator_user_ref    VARCHAR -- refers to user_account
  ,number_of_subkeys   VARCHAR
);

DROP TABLE IF EXISTS x509_v3_extensions;
CREATE TABLE  x509_v3_extensions( -- this is a 1 to 1 relation with windows_process_ext, it can be merged
   fk_x509_certificate_id              VARCHAR -- refers to x509_certificate
  ,basic_constraints                   VARCHAR
  ,description                         VARCHAR
  ,name_constraints                    VARCHAR
  ,policy_constraints                  VARCHAR
  ,key_usage                           VARCHAR
  ,extended_key_usage                  VARCHAR
  ,subject_key_identifier              VARCHAR
  ,authority_key_identifier            VARCHAR
  ,subject_alternative_name            VARCHAR
  ,issuer_alternative_name             VARCHAR
  ,subject_directory_attributes        VARCHAR
  ,crl_distribution_points             VARCHAR
  ,inhibit_any_policy                  VARCHAR
  ,private_key_usage_period_not_before VARCHAR
  ,private_key_usage_period_not_after  VARCHAR
  ,certificate_policies                VARCHAR
  ,policy_mappings                     VARCHAR
);

DROP TABLE IF EXISTS x509_certificate;
CREATE TABLE x509_certificate(
   pk_id                        VARCHAR -- unique GUID generated by application as a primary key, used to link to other tables in a one to many relationship
  ,fk_observed_data_id          VARCHAR -- refers to observed_data
  ,is_self_signed               VARCHAR -- "true", "false"
  ,version                      VARCHAR
  ,serial_number                VARCHAR
  ,signature_algorithm          VARCHAR
  ,issuer                       VARCHAR
  ,validity_not_before          VARCHAR
  ,validity_not_after           VARCHAR
  ,subject                      VARCHAR
  ,subject_public_key_algorithm VARCHAR
  ,subject_public_key_modulus   VARCHAR
  ,subject_public_key_exponent  VARCHAR
);

--
-- SDOS - STIX 2.0 Domain Objects
--

DROP TABLE IF EXISTS sdos_object;
CREATE TABLE sdos_object(
   fk_bundle_id         VARCHAR -- refers to bundle
  -- common attributes
  ,id                   VARCHAR
  ,created_by_ref       VARCHAR -- refers back to identity
  ,created              VARCHAR
  ,modified             VARCHAR
  ,revoked              VARCHAR -- "true", "false"
  ,name                 VARCHAR
  ,description          VARCHAR
  ,type                 VARCHAR -- type of sdos object reference: "threat-report", "attack-pattern", "campaign", "identity", "indicator", "malware",
                             -- "observed-data", "threat-actor", "tool", "vulnerability"

  -- common attributes (one to many relation)
  -- "labels" table
  -- "external_references" table
  -- "object_marking_refs" table
  -- "granular_markings" table

  -- object specific attributes

  -- campaign, intrusion_set, sighting
  ,first_seen           VARCHAR
  ,last_seen            VARCHAR

  -- campaign
  ,objective            VARCHAR

  -- identity
  ,identity_class       VARCHAR -- "individual", "group", "organization", "class", "unknown"
  ,contact_information  VARCHAR

  -- indicator
  ,pattern              VARCHAR
  ,valid_from           VARCHAR
  ,valid_until          VARCHAR

  -- intrusion_set, threat_actor
  ,resource_level       VARCHAR -- "individual", "club", "contest", "team", "organization", "government"
  ,primary_motivation   VARCHAR -- "accidental", "coercion", "dominance", "ideology", "notoriety", "organizational-gain",
                                -- "personal-gain", "personal-satisfaction", "revenge", "unpredictable"

  -- observed_data
  ,first_observed       VARCHAR
  ,last_observed        VARCHAR
  ,number_observed      VARCHAR -- "1" .. "999999999"

  -- report
  ,published            VARCHAR

  -- threat_actor
  ,sophistication       VARCHAR -- "none", "minimal", "intermediate", "advanced", "strategic", "expert", "innovator"

  -- tool
  ,tool_version         VARCHAR

  -- sighting
  ,count                VARCHAR -- "1" .. "999999999"
  ,sighting_of_ref      VARCHAR -- sdos object reference
  ,sighting_of_ref_type VARCHAR -- type of sdos object reference: "threat-report", "attack-pattern", "campaign", "identity", "indicator", "malware",
                                -- "observed-data", "threat-actor", "tool", "vulnerability"
  ,summary              VARCHAR -- "true", "false"

  -- X-MITRE support fields
  ,x_mitre_platforms_windows           VARCHAR
  ,x_mitre_platforms_macOS             VARCHAR
  ,x_mitre_platforms_linux             VARCHAR
  ,x_mitre_system_requirements         VARCHAR
  ,x_mitre_remote_support              VARCHAR
  ,x_mitre_network_requirements        VARCHAR
);

DROP TABLE IF EXISTS report_object_refs;
CREATE TABLE report_object_refs(
   fk_report_id          VARCHAR -- refers to report
  ,fk_object_id          VARCHAR -- sdos object reference
  ,object_reference_type VARCHAR -- "threat-report", "attack-pattern", "campaign", "identity", "indicator", "malware",
                                 -- "observed-data", "threat-actor", "tool", "vulnerability"
);

DROP TABLE IF EXISTS sighting_observed_data_refs;
CREATE TABLE sighting_observed_data_refs(
   fk_sighting_id            VARCHAR -- refers to sighting
  ,referenced_obsevable_type VARCHAR -- type of referenced observable : artifact, autonomous_system, directory,
                                     -- domain_name, email_addr, email_message, file, ipv4_addr, ipv6_addr,
                                     -- mac_addr, mutex, network_traffic, process, software, url, user_account,
                                     -- windows_registry_key, x509_certificate
  ,fk_observable_id          VARCHAR -- refers to any observable object
);

DROP TABLE IF EXISTS relationship;
CREATE TABLE relationship(
   fk_bundle_id      VARCHAR -- refers to bundle
  ,id                VARCHAR -- refers to relationship
  ,relationship_type VARCHAR -- type of referenced observable : artifact, autonomous_system, directory,
                             -- domain_name, email_addr, email_message, file, ipv4_addr, ipv6_addr,
                             -- mac_addr, mutex, network_traffic, process, software, url, user_account,
                             -- windows_registry_key, x509_certificate
  ,description       VARCHAR -- refers to any observable object
  ,source_ref        VARCHAR -- refers to sdos object
  ,source_ref_type   VARCHAR -- type of sdos object reference: "threat-report", "attack-pattern", "campaign", "identity", "indicator", "malware",
                             -- "observed-data", "threat-actor", "tool", "vulnerability"
  ,target_ref        VARCHAR -- refers to sdos object
  ,target_ref_type   VARCHAR -- type of sdos object reference: "threat-report", "attack-pattern", "campaign", "identity", "indicator", "malware",
                             -- "observed-data", "threat-actor", "tool", "vulnerability"
);

DROP TABLE IF EXISTS x_mitre_data_sources;
CREATE TABLE x_mitre_data_sources(
   fk_object_id        VARCHAR
  ,x_mitre_data_source VARCHAR
);

DROP TABLE IF EXISTS x_mitre_permissions_required;
CREATE TABLE x_mitre_permissions_required(
  fk_object_id                 VARCHAR
  ,x_mitre_permission_required VARCHAR
);

DROP TABLE IF EXISTS x_mitre_effective_permissions;
CREATE TABLE x_mitre_effective_permissions(
  fk_object_id                  VARCHAR
  ,x_mitre_effective_permission VARCHAR
);

DROP TABLE IF EXISTS x_mitre_contributors;
CREATE TABLE x_mitre_contributors(
  fk_object_id         VARCHAR
  ,x_mitre_contributor VARCHAR
);

DROP TABLE IF EXISTS x_mitre_defenses_bypassed;
CREATE TABLE x_mitre_defenses_bypassed(
  fk_object_id              VARCHAR
  ,x_mitre_defense_bypassed VARCHAR
);

DROP TABLE IF EXISTS x_mitre_aliases;
CREATE TABLE x_mitre_aliases(
  fk_object_id   VARCHAR
  ,x_mitre_alias VARCHAR
);

DROP TABLE IF EXISTS emulation_plan;
CREATE TABLE emulation_plan(
   fk_bundle_id   VARCHAR -- refers to bundle
  ,id             VARCHAR -- emulation_plan--GUID
  ,created_by_ref VARCHAR -- refers back to identity
  ,name           VARCHAR -- title
  ,description    VARCHAR
  ,created        VARCHAR
  ,modified       VARCHAR
  ,start_date     VARCHAR
  ,end_date       VARCHAR
  ,revoked        VARCHAR
);

DROP TABLE IF EXISTS emulation_plan_tags;
-- Emulation plan can have one or more tags
CREATE TABLE emulation_plan_tags(
   fk_emulation_plan_id VARCHAR -- refers to an emulation plan
  ,tag                  VARCHAR -- tag value, can be string or color
  ,tag_type             VARCHAR -- either "string" or "color"
);

DROP TABLE IF EXISTS testing_guideline;
-- Emulation plans have one or more testing plans/guidelines
-- For the same entity (intrusion-set, malware or tool) more than one testing plan can exist
CREATE TABLE testing_guideline(
   fk_emulation_plan_id VARCHAR -- refers to an emulation plan
  ,id                   VARCHAR -- "testing-guideline--GUID"
  ,name                 VARCHAR -- guideline title
  ,description          VARCHAR -- guideline description
  ,framework            VARCHAR -- examples might be "builtin", "metasploit", "cobalt-strike"
  ,implementation       VARCHAR -- for example, the command
  ,result               VARCHAR -- "not-tested", "succeeded" or "failed" (from a red-teaming perspective)
  ,detected_ioc         VARCHAR -- documents the detected IOC (found by blue team)
  ,lessons_learned      VARCHAR -- lessons learned
  ,revoked              VARCHAR
  ,test_completed       VARCHAR -- was test completed
);

DROP TABLE IF EXISTS testing_guideline_technique;
-- Each test is associated with one or more ATTACK techniques
CREATE TABLE testing_guideline_technique(
   fk_testing_guideline_id VARCHAR -- refers to a testing guideline
  ,fk_attack_id            VARCHAR -- ATTACK technique ID
  ,fk_attack_external_id   VARCHAR -- ATTACK technique external ID (optimization to reduce joins)
);

DROP TABLE IF EXISTS testing_guideline_tags;
-- Testing plan can have one or more tags
CREATE TABLE testing_guideline_tags(
   fk_testing_guideline_id VARCHAR -- refers to a testing guideline
  ,tag                     VARCHAR -- tag value, can be string or color
  ,tag_type                VARCHAR -- either "text" or "color"
);