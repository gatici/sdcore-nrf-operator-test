# SD-Core NRF K8s Terraform Module

This SD-Core NRF K8s Terraform module aims to deploy the [sdcore-nrf-k8s charm](https://charmhub.io/sdcore-nrf-k8s) via Terraform.

## Getting Started

### Install requirements

The following software and tools needs to be installed and should be running in the local environment.

- `microk8s`
- `juju 3.x`
- `terrafom`

Install Microk8s and enable storage add-on:

```console
sudo snap install microk8s --channel=1.27-strict/stable
sudo usermod -a -G snap_microk8s $USER
newgrp snap_microk8s
sudo microk8s enable hostpath-storage
```

Install Juju:

```console
sudo snap install juju --channel=3.1/stable
```

Install Terraform:

```console
sudo snap install --classic terraform
```

### Bootstrap the Juju using Microk8s and create a model to deploy Terraform module

Bootstrap Juju Controller:

```console
juju bootstrap microk8s
```

### Deploy Mongodb-k8s using Terraform

Initialise the provider:

```console
terraform init
```

Customize the configuration inputs under `terraform.tfvars` file according to requirement.

Sample contents of `terraform.tfvars` file:

```yaml
model_name ="test"
```

Run Terraform plan by providing var-file:

```console
terraform plan -var-file="terraform.tfvars" 
```

Deploy the resources, skip the approval.

```console
terraform apply -auto-approve 
```

```{note}
After running above command, if you get the error below, run the `terraform apply -auto-approve` again.
`Unable to create application, got error: model "<model_name>" not found`
```

### Check the Output

Run `juju switch <juju model>` to switch to the target Juju model and observe the status of the application.

```console
juju status --relations
```

The output should be similar to the following:

```console
Model  Controller          Cloud/Region        Version  SLA          Timestamp
test   microk8s-localhost  microk8s/localhost  3.1.7    unsupported  11:54:07+03:00

App                       Version  Status  Scale  Charm                     Channel   Rev  Address         Exposed  Message
mongodb-k8s                        active      1  mongodb-k8s               6/beta     38  10.152.183.119  no       
nrf                                active      1  sdcore-nrf-k8s            1.3/edge   10  10.152.183.130  no       
self-signed-certificates           active      1  self-signed-certificates  beta       57  10.152.183.65   no       

Unit                         Workload  Agent  Address      Ports  Message
mongodb-k8s/0*               active    idle   10.1.146.47         
nrf/0*                       active    idle   10.1.146.58         
self-signed-certificates/0*  active    idle   10.1.146.56         

Integration provider                   Requirer                    Interface         Type     Message
mongodb-k8s:database                   nrf:database                mongodb_client    regular  
mongodb-k8s:database-peers             mongodb-k8s:database-peers  mongodb-peers     peer     
self-signed-certificates:certificates  nrf:certificates            tls-certificates  regular 
```

### Clean up 

Remove the application:

```console
terraform destroy -auto-approve
```

