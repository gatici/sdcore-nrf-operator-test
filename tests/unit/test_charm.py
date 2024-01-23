# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import Mock, patch

from ops import testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

from charm import NRFOperatorCharm  # type: ignore[import]

DB_APPLICATION_NAME = "mongodb-k8s"
BASE_CONFIG_PATH = "/etc/nrf"
CONFIG_FILE_NAME = "nrfcfg.yaml"
TLS_APPLICATION_NAME = "self-signed-certificates"
TLS_RELATION_NAME = "certificates"


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = testing.Harness(NRFOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(is_leader=True)
        self.harness.begin()

    def _create_database_relation(self) -> int:
        """Create a database relation.

        Returns:
            relation_id: ID of the created relation
        """
        relation_id = self.harness.add_relation(
            relation_name="database",
            remote_app=DB_APPLICATION_NAME,
        )
        self.harness.add_relation_unit(
            relation_id=relation_id,
            remote_unit_name=f"{DB_APPLICATION_NAME}/0",
        )
        return relation_id

    def _create_database_relation_and_populate_data(self) -> int:
        """Create a database relation and set the database information.

        Returns:
            relation_id: ID of the created relation
        """
        database_relation_id = self._create_database_relation()
        self.harness.update_relation_data(
            relation_id=database_relation_id,
            app_or_unit=DB_APPLICATION_NAME,
            key_values={
                "username": "dummy",
                "password": "dummy",
                "uris": "http://dummy",
            },
        )
        return database_relation_id

    @staticmethod
    def _read_file(path: str) -> str:
        """Reads a file and returns as a string.

        Args:
            path (str): path to the file.

        Returns:
            str: content of the file.
        """
        with open(path, "r") as f:
            content = f.read()
        return content

    def test_given_database_relation_not_created_when_pebble_ready_then_status_is_blocked(self):
        self.harness.container_pebble_ready(container_name="nrf")

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for database relation to be created"),
        )

    def test_given_certificates_relation_not_created_when_pebble_ready_then_status_is_blocked(
        self,
    ):
        self.harness.container_pebble_ready(container_name="nrf")
        self._create_database_relation()

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus(f"Waiting for {TLS_RELATION_NAME} relation to be created"),
        )

    @patch("charm.check_output")
    def test_given_nrf_charm_in_active_state_when_database_relation_breaks_then_status_is_blocked(
        self,
        patch_check_output,
    ):
        self.harness.add_storage("config", attach=True)
        self.harness.add_storage("certs", attach=True)
        certificate = "Whatever certificate content"
        root = self.harness.get_filesystem_root("nrf")
        (root / "support/TLS/nrf.pem").write_text(certificate)
        patch_check_output.return_value = b"1.1.1.1"
        database_relation_id = self._create_database_relation_and_populate_data()
        self.harness.add_relation(relation_name=TLS_RELATION_NAME, remote_app=TLS_APPLICATION_NAME)
        self.harness.container_pebble_ready(container_name="nrf")

        self.harness.remove_relation(database_relation_id)

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for database relation"),
        )

    def test_given_database_not_available_when_pebble_ready_then_status_is_waiting(
        self,
    ):
        self._create_database_relation()
        self.harness.add_relation(relation_name=TLS_RELATION_NAME, remote_app=TLS_APPLICATION_NAME)
        self.harness.container_pebble_ready(container_name="nrf")
        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for the database to be available"),
        )

    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseRequires.is_resource_created")
    def test_given_database_information_not_available_when_pebble_ready_then_status_is_waiting(
        self,
        patch_is_resource_created,
    ):
        patch_is_resource_created.return_value = True
        self._create_database_relation()
        self.harness.add_relation(relation_name=TLS_RELATION_NAME, remote_app=TLS_APPLICATION_NAME)
        self.harness.container_pebble_ready(container_name="nrf")
        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for database URI"),
        )

    def test_given_storage_not_attached_when_pebble_ready_then_status_is_waiting(
        self,
    ):
        self._create_database_relation_and_populate_data()
        self.harness.add_relation(relation_name=TLS_RELATION_NAME, remote_app=TLS_APPLICATION_NAME)
        self.harness.container_pebble_ready(container_name="nrf")
        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for storage to be attached"),
        )

    @patch("charm.check_output")
    @patch("charm.generate_private_key")
    def test_given_certificates_not_stored_when_pebble_ready_then_status_is_waiting(
        self,
        patch_generate_private_key,
        patch_check_output,
    ):
        self.harness.add_storage("config", attach=True)
        self.harness.add_storage("certs", attach=True)
        private_key = b"whatever key content"
        patch_generate_private_key.return_value = private_key
        patch_check_output.return_value = b"1.1.1.1"
        self.harness.set_can_connect(container="nrf", val=True)
        self._create_database_relation_and_populate_data()
        self.harness.add_relation(relation_name=TLS_RELATION_NAME, remote_app=TLS_APPLICATION_NAME)
        self.harness.container_pebble_ready("nrf")
        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for certificates to be stored"),
        )

    @patch("charm.check_output")
    @patch("charm.generate_private_key")
    def test_given_database_info_and_storage_attached_and_certs_stored_when_pebble_ready_then_config_file_is_rendered_and_pushed(  # noqa: E501
        self,
        patch_generate_private_key,
        patch_check_output,
    ):
        self.harness.add_storage("config", attach=True)
        self.harness.add_storage("certs", attach=True)
        root = self.harness.get_filesystem_root("nrf")
        private_key = b"whatever key content"
        patch_generate_private_key.return_value = private_key
        patch_check_output.return_value = b"1.1.1.1"
        csr = "Whatever CSR content"
        (root / "support/TLS/nrf.csr").write_text(csr)
        (root / f"etc/nrf/{CONFIG_FILE_NAME}").write_text("Dummy Content")
        certificate = "Whatever certificate content"
        event = Mock()
        event.certificate = certificate
        event.certificate_signing_request = csr
        self.harness.set_can_connect(container="nrf", val=True)
        self._create_database_relation_and_populate_data()
        self.harness.add_relation(relation_name=TLS_RELATION_NAME, remote_app=TLS_APPLICATION_NAME)
        self.harness.charm._on_certificate_available(event=event)
        self.harness.container_pebble_ready(container_name="nrf")
        self.assertEqual(self.harness.model.unit.status, ActiveStatus(""))
        with open("tests/unit/expected_config/config.conf") as expected_config_file:
            expected_content = expected_config_file.read()
            self.assertEqual(
                (root / f"etc/nrf/{CONFIG_FILE_NAME}").read_text(), expected_content.strip()
            )

    @patch("charm.check_output")
    def test_given_content_of_config_file_not_changed_when_pebble_ready_then_config_file_is_not_pushed(  # noqa: E501
        self,
        patch_check_output,
    ):
        self.harness.add_storage("config", attach=True)
        self.harness.add_storage("certs", attach=True)
        certificate = "Whatever certificate content"
        root = self.harness.get_filesystem_root("nrf")
        (root / "support/TLS/nrf.pem").write_text(certificate)
        (root / f"etc/nrf/{CONFIG_FILE_NAME}").write_text(
            self._read_file("tests/unit/expected_config/config.conf").strip()
        )
        config_modification_time = (root / f"etc/nrf/{CONFIG_FILE_NAME}").stat().st_mtime
        patch_check_output.return_value = b"1.1.1.1"
        self.harness.set_can_connect(container="nrf", val=True)
        self._create_database_relation_and_populate_data()
        self.harness.container_pebble_ready(container_name="nrf")
        self.assertEqual(
            (root / f"etc/nrf/{CONFIG_FILE_NAME}").stat().st_mtime, config_modification_time
        )

    @patch("charm.check_output")
    def test_given_config_pushed_when_pebble_ready_then_pebble_plan_is_applied(
        self,
        patch_check_output,
    ):
        patch_check_output.return_value = b"1.1.1.1"
        self.harness.add_storage("config", attach=True)
        self.harness.add_storage("certs", attach=True)
        certificate = "Whatever certificate content"
        root = self.harness.get_filesystem_root("nrf")
        (root / "support/TLS/nrf.pem").write_text(certificate)
        (root / f"etc/nrf/{CONFIG_FILE_NAME}").write_text(
            self._read_file("tests/unit/expected_config/config.conf").strip()
        )

        self.harness.set_can_connect(container="nrf", val=True)
        self._create_database_relation_and_populate_data()
        self.harness.add_relation(relation_name=TLS_RELATION_NAME, remote_app=TLS_APPLICATION_NAME)

        self.harness.container_pebble_ready(container_name="nrf")

        expected_plan = {
            "services": {
                "nrf": {
                    "override": "replace",
                    "command": "/bin/nrf --nrfcfg /etc/nrf/nrfcfg.yaml",
                    "startup": "enabled",
                    "environment": {
                        "GRPC_GO_LOG_VERBOSITY_LEVEL": "99",
                        "GRPC_GO_LOG_SEVERITY_LEVEL": "info",
                        "GRPC_TRACE": "all",
                        "GRPC_VERBOSITY": "debug",
                        "MANAGED_BY_CONFIG_POD": "true",
                    },
                }
            },
        }

        updated_plan = self.harness.get_container_pebble_plan("nrf").to_dict()

        self.assertEqual(expected_plan, updated_plan)

    @patch("charm.check_output")
    def test_given_database_relation_is_created_and_config_file_is_written_when_pebble_ready_then_status_is_active(  # noqa: E501
        self,
        patch_check_output,
    ):
        patch_check_output.return_value = b"1.1.1.1"
        self.harness.add_storage("config", attach=True)
        self.harness.add_storage("certs", attach=True)
        certificate = "Whatever certificate content"
        root = self.harness.get_filesystem_root("nrf")
        (root / "support/TLS/nrf.pem").write_text(certificate)
        (root / f"etc/nrf/{CONFIG_FILE_NAME}").write_text(
            self._read_file("tests/unit/expected_config/config.conf").strip()
        )

        self.harness.set_can_connect(container="nrf", val=True)

        self._create_database_relation_and_populate_data()
        self.harness.add_relation(relation_name=TLS_RELATION_NAME, remote_app=TLS_APPLICATION_NAME)

        self.harness.container_pebble_ready("nrf")

        self.assertEqual(self.harness.model.unit.status, ActiveStatus())

    @patch("charm.check_output")
    def test_given_ip_not_available_when_pebble_ready_then_status_is_waiting(
        self,
        patch_check_output,
    ):
        patch_check_output.return_value = b""
        self.harness.add_storage("config", attach=True)
        self.harness.add_storage("certs", attach=True)
        certificate = "Whatever certificate content"
        root = self.harness.get_filesystem_root("nrf")
        (root / "support/TLS/nrf.pem").write_text(certificate)
        (root / f"etc/nrf/{CONFIG_FILE_NAME}").write_text(
            self._read_file("tests/unit/expected_config/config.conf").strip()
        )

        self.harness.set_can_connect(container="nrf", val=True)

        self._create_database_relation_and_populate_data()
        self.harness.add_relation(relation_name=TLS_RELATION_NAME, remote_app=TLS_APPLICATION_NAME)

        self.harness.container_pebble_ready("nrf")

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for pod IP address to be available"),
        )

    @patch("charm.check_output")
    def test_given_https_nrf_url_and_service_is_running_when_fiveg_nrf_relation_joined_then_nrf_url_is_in_relation_databag(  # noqa: E501
        self,
        patch_check_output,
    ):
        patch_check_output.return_value = b"1.1.1.1"
        self.harness.add_storage("config", attach=True)
        self.harness.add_storage("certs", attach=True)
        certificate = "Whatever certificate content"
        root = self.harness.get_filesystem_root("nrf")
        (root / "support/TLS/nrf.pem").write_text(certificate)
        (root / f"etc/nrf/{CONFIG_FILE_NAME}").write_text(
            self._read_file("tests/unit/expected_config/config.conf").strip()
        )

        self._create_database_relation_and_populate_data()
        self.harness.add_relation(relation_name=TLS_RELATION_NAME, remote_app=TLS_APPLICATION_NAME)

        self.harness.set_can_connect(container="nrf", val=True)
        self.harness.container_pebble_ready("nrf")

        relation_id = self.harness.add_relation(
            relation_name="fiveg-nrf",
            remote_app="nrf-requirer",
        )
        self.harness.add_relation_unit(relation_id=relation_id, remote_unit_name="nrf-requirer/0")
        relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name
        )
        self.assertEqual(relation_data["url"], "https://nrf:29510")

    @patch("charm.check_output")
    def test_service_starts_running_after_nrf_relation_joined_when_fiveg_pebble_ready_then_nrf_url_is_in_relation_databag(  # noqa: E501
        self, patch_check_output
    ):
        patch_check_output.return_value = b"1.1.1.1"
        self.harness.add_storage("config", attach=True)
        self.harness.add_storage("certs", attach=True)
        certificate = "Whatever certificate content"
        root = self.harness.get_filesystem_root("nrf")
        (root / "support/TLS/nrf.pem").write_text(certificate)
        (root / f"etc/nrf/{CONFIG_FILE_NAME}").write_text(
            self._read_file("tests/unit/expected_config/config.conf").strip()
        )

        self.harness.set_can_connect(container="nrf", val=False)

        relation_1_id = self.harness.add_relation(
            relation_name="fiveg-nrf",
            remote_app="nrf-requirer-1",
        )

        relation_2_id = self.harness.add_relation(
            relation_name="fiveg-nrf",
            remote_app="nrf-requirer-2",
        )
        self.harness.add_relation_unit(
            relation_id=relation_1_id, remote_unit_name="nrf-requirer-1/0"
        )
        self.harness.add_relation_unit(
            relation_id=relation_2_id, remote_unit_name="nrf-requirer-2/0"
        )

        self._create_database_relation_and_populate_data()
        self.harness.add_relation(relation_name=TLS_RELATION_NAME, remote_app=TLS_APPLICATION_NAME)

        self.harness.container_pebble_ready("nrf")

        relation_1_data = self.harness.get_relation_data(
            relation_id=relation_1_id, app_or_unit=self.harness.charm.app.name
        )
        relation_2_data = self.harness.get_relation_data(
            relation_id=relation_2_id, app_or_unit=self.harness.charm.app.name
        )
        self.assertEqual(relation_1_data["url"], "https://nrf:29510")
        self.assertEqual(relation_2_data["url"], "https://nrf:29510")

    @patch("charm.generate_private_key")
    def test_given_can_connect_when_on_certificates_relation_created_then_private_key_is_generated(
        self, patch_generate_private_key
    ):
        private_key = b"whatever key content"
        self.harness.add_storage("config", attach=True)
        self.harness.add_storage("certs", attach=True)
        root = self.harness.get_filesystem_root("nrf")
        self.harness.set_can_connect(container="nrf", val=True)
        patch_generate_private_key.return_value = private_key

        self.harness.charm._on_certificates_relation_created(event=Mock)

        self.assertEqual((root / "support/TLS/nrf.key").read_text(), private_key.decode())

    def test_given_certificates_are_stored_when_on_certificates_relation_broken_then_certificates_are_removed(  # noqa: E501
        self,
    ):
        self.harness.add_storage("certs", attach=True)
        private_key = "whatever key content"
        csr = "Whatever CSR content"
        certificate = "Whatever certificate content"
        root = self.harness.get_filesystem_root("nrf")
        (root / "support/TLS/nrf.key").write_text(private_key)
        (root / "support/TLS/nrf.csr").write_text(csr)
        (root / "support/TLS/nrf.pem").write_text(certificate)
        self.harness.set_can_connect(container="nrf", val=True)

        self.harness.charm._on_certificates_relation_broken(event=Mock)

        with self.assertRaises(FileNotFoundError):
            (root / "support/TLS/nrf.key").read_text()
        with self.assertRaises(FileNotFoundError):
            (root / "support/TLS/nrf.pem").read_text()
        with self.assertRaises(FileNotFoundError):
            (root / "support/TLS/nrf.csr").read_text()

    def test_given_certificates_are_stored_when_on_certificates_relation_broken_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.harness.add_storage("certs", attach=True)
        private_key = "whatever key content"
        csr = "Whatever CSR content"
        certificate = "Whatever certificate content"
        root = self.harness.get_filesystem_root("nrf")
        (root / "support/TLS/nrf.key").write_text(private_key)
        (root / "support/TLS/nrf.csr").write_text(csr)
        (root / "support/TLS/nrf.pem").write_text(certificate)
        self.harness.set_can_connect(container="nrf", val=True)
        self._create_database_relation_and_populate_data()
        self.harness.add_relation(relation_name=TLS_RELATION_NAME, remote_app=TLS_APPLICATION_NAME)
        self.harness.charm._on_certificates_relation_broken(event=Mock())
        self.assertEqual(
            self.harness.charm.unit.status,
            BlockedStatus(f"Waiting for {TLS_RELATION_NAME} relation to be created"),
        )

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
        new=Mock,
    )
    @patch("charm.generate_csr")
    def test_given_private_key_exists_when_on_certificates_relation_joined_then_csr_is_generated(
        self, patch_generate_csr
    ):
        self.harness.add_storage("certs", attach=True)
        private_key = "whatever key content"
        root = self.harness.get_filesystem_root("nrf")
        (root / "support/TLS/nrf.key").write_text(private_key)
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr
        self.harness.set_can_connect(container="nrf", val=True)

        self.harness.charm._on_certificates_relation_joined(event=Mock)

        self.assertEqual((root / "support/TLS/nrf.csr").read_text(), csr.decode())

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
    )
    @patch("charm.generate_csr")
    def test_given_private_key_exists_and_cert_not_yet_requested_when_on_certificates_relation_joined_then_cert_is_requested(  # noqa: E501
        self,
        patch_generate_csr,
        patch_request_certificate_creation,
    ):
        self.harness.add_storage("certs", attach=True)
        private_key = "whatever key content"
        root = self.harness.get_filesystem_root("nrf")
        (root / "support/TLS/nrf.key").write_text(private_key)
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr
        self.harness.set_can_connect(container="nrf", val=True)

        self.harness.charm._on_certificates_relation_joined(event=Mock)

        patch_request_certificate_creation.assert_called_with(certificate_signing_request=csr)

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
    )
    def test_given_cert_already_stored_when_on_certificates_relation_joined_then_cert_is_not_requested(  # noqa: E501
        self,
        patch_request_certificate_creation,
    ):
        self.harness.add_storage("certs", attach=True)
        private_key = "whatever key content"
        certificate = "Whatever certificate content"
        root = self.harness.get_filesystem_root("nrf")
        (root / "support/TLS/nrf.key").write_text(private_key)
        (root / "support/TLS/nrf.pem").write_text(certificate)
        self.harness.set_can_connect(container="nrf", val=True)

        self.harness.charm._on_certificates_relation_joined(event=Mock)

        patch_request_certificate_creation.assert_not_called()

    def test_given_csr_matches_stored_one_when_certificate_available_then_certificate_is_pushed(
        self,
    ):
        self.harness.add_storage("certs", attach=True)
        csr = "Whatever CSR content"
        certificate = "Whatever certificate content"
        root = self.harness.get_filesystem_root("nrf")
        (root / "support/TLS/nrf.csr").write_text(csr)
        event = Mock()
        event.certificate = certificate
        event.certificate_signing_request = csr
        self.harness.set_can_connect(container="nrf", val=True)

        self.harness.charm._on_certificate_available(event=event)

        self.assertEqual((root / "support/TLS/nrf.pem").read_text(), certificate)

    def test_given_csr_doesnt_match_stored_one_when_certificate_available_then_certificate_is_not_pushed(  # noqa: E501
        self,
    ):
        self.harness.add_storage("certs", attach=True)
        csr = "Stored CSR content"
        certificate = "Whatever certificate content"
        root = self.harness.get_filesystem_root("nrf")
        (root / "support/TLS/nrf.csr").write_text(csr)
        event = Mock()
        event.certificate = certificate
        event.certificate_signing_request = "Relation CSR content (different from stored one)"
        self.harness.set_can_connect(container="nrf", val=True)

        self.harness.charm._on_certificate_available(event=event)

        with self.assertRaises(FileNotFoundError):
            (root / "support/TLS/nrf.pem").read_text()

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
    )
    @patch("charm.generate_csr")
    def test_given_certificate_does_not_match_stored_one_when_certificate_expiring_then_certificate_is_not_requested(  # noqa: E501
        self, patch_generate_csr, patch_request_certificate_creation
    ):
        self.harness.add_storage("certs", attach=True)
        certificate = "Stored certificate content"
        root = self.harness.get_filesystem_root("nrf")
        (root / "support/TLS/nrf.pem").write_text(certificate)
        event = Mock()
        event.certificate = "Relation certificate content (different from stored)"
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr
        self.harness.set_can_connect(container="nrf", val=True)

        self.harness.charm._on_certificate_expiring(event=event)

        patch_request_certificate_creation.assert_not_called()

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
    )
    @patch("charm.generate_csr")
    def test_given_certificate_matches_stored_one_when_certificate_expiring_then_certificate_is_requested(  # noqa: E501
        self, patch_generate_csr, patch_request_certificate_creation
    ):
        self.harness.add_storage("certs", attach=True)
        private_key = "whatever key content"
        certificate = "whatever certificate content"
        root = self.harness.get_filesystem_root("nrf")
        (root / "support/TLS/nrf.key").write_text(private_key)
        (root / "support/TLS/nrf.pem").write_text(certificate)
        event = Mock()
        event.certificate = certificate
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr
        self.harness.set_can_connect(container="nrf", val=True)

        self.harness.charm._on_certificate_expiring(event=event)

        patch_request_certificate_creation.assert_called_with(certificate_signing_request=csr)
