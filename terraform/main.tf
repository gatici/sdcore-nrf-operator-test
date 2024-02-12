resource "juju_model" "sdcore" {
  name = var.model_name
}

resource "juju_application" "nrf" {
  name = "nrf"
  model = juju_model.sdcore.name

  charm {
    name = "sdcore-nrf-k8s"
    channel = var.channel
  }

  units = 1
  trust = true
}

module "mongodb-k8s" {
  source     = "git::https://github.com/gatici/mongodb-k8s-test.git//terraform"
  model_name = juju_model.sdcore.name
}

module "self-signed-certificates" {
  source     = "git::https://github.com/gatici/self-signed-certificates-test.git//terraform"
  model_name = juju_model.sdcore.name
}

resource "juju_integration" "nrf-db" {
  model = juju_model.sdcore.name

  application {
    name     = juju_application.nrf.name
    endpoint = "database"
  }

  application {
    name     = module.mongodb-k8s.db_application_name
    endpoint = "database"
  }
}

resource "juju_integration" "nrf-certs" {
  model = juju_model.sdcore.name

  application {
    name     = juju_application.nrf.name
    endpoint = "certificates"
  }

  application {
    name     = module.self-signed-certificates.certs_application_name
    endpoint = "certificates"
  }
}

