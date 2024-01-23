#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
from collections import Counter
from pathlib import Path

import pytest
import yaml
from juju.application import Application
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]
DB_APPLICATION_NAME = "mongodb"
DB_CHARM_NAME = "mongodb-k8s"
TLS_APPLICATION_NAME = "self-signed-certificates"


@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def deploy_mongodb(ops_test):
    await ops_test.model.deploy(
        DB_CHARM_NAME, application_name=DB_APPLICATION_NAME, channel="6/beta", trust=True
    )


@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def deploy_self_signed_certificates(ops_test):
    await ops_test.model.deploy(
        TLS_APPLICATION_NAME,
        application_name=TLS_APPLICATION_NAME,
        channel="beta",
    )


@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def build_and_deploy(ops_test):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    charm = await ops_test.build_charm(".")
    resources = {"nrf-image": METADATA["resources"]["nrf-image"]["upstream-source"]}
    await ops_test.model.deploy(
        charm,
        resources=resources,
        application_name=APP_NAME,
        series="jammy",
    )


@pytest.mark.abort_on_fail
async def test_given_charm_is_built_when_deployed_then_status_is_blocked(
    ops_test, build_and_deploy, deploy_mongodb, deploy_self_signed_certificates
):
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="blocked",
        timeout=1000,
    )


async def test_given_charm_is_deployed_when_relate_to_mongo_and_certificates_then_status_is_active(
    ops_test: OpsTest, build_and_deploy
):
    assert ops_test.model
    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:database", relation2=f"{DB_APPLICATION_NAME}:database"
    )
    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:certificates", relation2=f"{TLS_APPLICATION_NAME}:certificates"
    )
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", timeout=1000)


@pytest.mark.abort_on_fail
async def test_remove_tls_and_wait_for_blocked_status(ops_test, build_and_deploy):
    await ops_test.model.remove_application(TLS_APPLICATION_NAME, block_until_done=True)  # type: ignore[union-attr]  # noqa: E501
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="blocked", timeout=60)  # type: ignore[union-attr]  # noqa: E501


@pytest.mark.abort_on_fail
async def test_restore_tls_and_wait_for_active_status(ops_test: OpsTest, build_and_deploy):
    assert ops_test.model
    await ops_test.model.deploy(
        TLS_APPLICATION_NAME,
        application_name=TLS_APPLICATION_NAME,
        channel="beta",
        trust=True,
    )
    await ops_test.model.integrate(relation1=APP_NAME, relation2=TLS_APPLICATION_NAME)
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", timeout=1000)


@pytest.mark.skip(
    reason="Bug in MongoDB: https://github.com/canonical/mongodb-k8s-operator/issues/218"
)
@pytest.mark.abort_on_fail
async def test_remove_database_and_wait_for_blocked_status(ops_test: OpsTest, build_and_deploy):
    assert ops_test.model
    await ops_test.model.remove_application(DB_APPLICATION_NAME, block_until_done=True)
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="blocked", timeout=60)


@pytest.mark.skip(
    reason="Bug in MongoDB: https://github.com/canonical/mongodb-k8s-operator/issues/218"
)
@pytest.mark.abort_on_fail
async def test_restore_database_and_wait_for_active_status(ops_test: OpsTest, build_and_deploy):
    assert ops_test.model
    await ops_test.model.deploy(
        DB_CHARM_NAME,
        application_name=DB_APPLICATION_NAME,
        channel="5/edge",
        trust=True,
    )
    await ops_test.model.integrate(relation1=APP_NAME, relation2=DB_APPLICATION_NAME)
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", timeout=1000)


@pytest.mark.abort_on_fail
async def test_when_scale_nrf_beyond_1_then_only_one_unit_is_active(
    ops_test: OpsTest, build_and_deploy
):
    assert ops_test.model
    assert isinstance(app := ops_test.model.applications[APP_NAME], Application)
    await app.scale(3)
    await ops_test.model.wait_for_idle(apps=[APP_NAME], timeout=1000, wait_for_at_least_units=3)
    unit_statuses = Counter(unit.workload_status for unit in app.units)
    assert unit_statuses.get("active") == 1
    assert unit_statuses.get("blocked") == 2


async def test_remove_nrf(ops_test: OpsTest, build_and_deploy):
    assert ops_test.model
    await ops_test.model.remove_application(APP_NAME, block_until_done=True)
