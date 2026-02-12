// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC

#include "config.h"
#include "test_common.h"

int main(void) {
	char config_path[512];
	struct ota_config cfg;
	int rc;

	TEST_ASSERT_INT_EQ(0, test_data_path(config_path, sizeof(config_path),
					     "config_valid.ini"));
	rc = config_load(config_path, &cfg);
	TEST_ASSERT_INT_EQ(0, rc);
	TEST_ASSERT_STR_EQ("https://updates.example.com", cfg.server_url);
	TEST_ASSERT_STR_EQ("/etc/ota_fetch/ca.pem", cfg.tls_ca_cert);
	TEST_ASSERT_STR_EQ("/etc/ota_fetch/client.crt", cfg.tls_client_cert);
	TEST_ASSERT_STR_EQ("/etc/ota_fetch/client.key", cfg.tls_client_key);
	TEST_ASSERT_INT_EQ(5, cfg.connect_timeout);
	TEST_ASSERT_INT_EQ(30, cfg.transfer_timeout);
	TEST_ASSERT_INT_EQ(3, cfg.retry_attempts);
	TEST_ASSERT_STR_EQ("/var/lib/ota_fetch/inbox", cfg.inbox_manifest_dir);
	TEST_ASSERT_STR_EQ("/var/lib/ota_fetch/current",
			   cfg.current_manifest_dir);
	TEST_ASSERT_STR_EQ("/etc/ota_fetch/root_ca.pem", cfg.manifest_ca_cert);
	TEST_ASSERT_STR_EQ("h4-gw", cfg.device_id);
	config_free(&cfg);

	TEST_ASSERT_INT_EQ(0, test_data_path(config_path, sizeof(config_path),
					     "config_missing_required.ini"));
	rc = config_load(config_path, &cfg);
	TEST_ASSERT(rc != 0);

	return 0;
}
