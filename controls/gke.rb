# Copyright 2020 Darkbit.io
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

title 'Evaluate GKE Cluster Configuration Best Practices'

project_id = attribute('project_id')
location = attribute('location')
clustername = attribute('clustername')

control "gke-1" do
  impact 0.8

  title "Ensure Stackdriver Logging and Monitoring is configured"

  desc "Exporting logs and metrics to a dedicated, persistent datastore such as Stackdriver ensures availability of audit data following a cluster security event, and provides a central location for analysis of log and metric data collated from multiple sources."
  desc "remediation", "Ensure `--enable-stackdriver-kubernetes` is set during cluster configuration, or run `gcloud container clusters update` and pass the `--enable-stackdriver-kubernetes` flag to enable the addons."
  desc "validation", "Run `gcloud container clusters describe` and review the configuration under `loggingService` and `monitoringService`.  They should be configured with `logging.googleapis.com/kubernetes` and `monitoring.googleapis.com/kubernetes`, respectively."

  tag platform: "GCP"
  tag category: "Logging and Monitoring"
  tag resource: "GKE"
  tag effort: 0.2

  ref "GKE Monitoring and Logging", url: "https://cloud.google.com/monitoring/kubernetes-engine"

  describe "#{project_id}/#{location}/#{clustername}:" do
    subject { google_container_regional_cluster(project: project_id, location: location, name: clustername) }
    its('logging_service') { should match /^logging.googleapis.com\/kubernetes/ }
    its('monitoring_service') { should match /^monitoring.googleapis.com\/kubernetes/ }
  end
end

control "gke-2" do
  impact 1.0

  title "Ensure Basic Authentication is disabled"

  desc "Until GKE 1.12, Basic Authentication was enabled by default on all clusters unless explicitly disabled.  Clusters that were created at or before version 1.12 and have been upgraded since will still have a valid username and password credential that grants full cluster access.  These credentials cannot be revoked or rotated without recreating the cluster.  Furthermore, they are available in clear-text via the `gcloud container clusters list/get` command, and many IAM Roles contain the `container.clusters.get` and `container.clusters.list` permissions, including `Project Viewer`.  When coupled with network access to the GKE API server, a clear path to become `cluster-admin` is possible."
  desc "remediation", "Recreate the GKE cluster from a recent version (1.12+) ensuring the `--no-enable-basic-auth` flag set or supply a <blank> value for the `master_auth.username` field when using Terraform."
  desc "validation", "Run `gcloud container clusters get` and review the `masterAuth` configuration block.  There should not be a `username` and `password` field with values."

  tag platform: "GCP"
  tag category: "Identity and Access Management"
  tag resource: "GKE"
  tag effort: 0.9

  ref "Auth", url: "https://cloud.google.com/kubernetes-engine/docs/how-to/iam-integration"

  describe "#{project_id}/#{location}/#{clustername}:" do
    subject { google_container_regional_cluster(project: project_id, location: location, name: clustername) }
    its('master_auth.username') { should cmp nil }
  end
end

control "gke-3" do
  impact 0.5

  title "Ensure GKE Nodes are not public"

  desc "By default, GKE nodes are created with both private and public IP addresses assigned, and the default Firewall Rules in the default Network permit remote access via SSH on TCP/22 from `0.0.0.0/0`.  Preventing GKE Nodes from being assigned a public IP address ensures that remote access attempts using SSH cannot be routed from the public Internet.  Should a pod become compromised and escape to the underlying node, it's possible to use that access to add SSH credentials to the host configuration.  However, that node will not be directly accessible from the Internet for SSH access if a public IP is not assigned."
  desc "remediation", "Recreate the GKE cluster ensuring the `--enable-private-nodes` flag is configured.  Ensure administrators have another mechanism such as a Bastion Host in the same VPC or Cloud Identity-Aware Proxy access is available if SSH access is still required."
  desc "validation", "Run `gcloud container clusters get` and review the `privateClusterConfig` configuration block. Ensure `enablePrivateNodes` is set to `true`."

  tag platform: "GCP"
  tag category: "Network Access Control"
  tag resource: "GKE"
  tag effort: 0.9

  ref "GKE Private Nodes", url: "https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters"

  describe "#{project_id}/#{location}/#{clustername}:" do
    subject { google_container_regional_cluster(project: project_id, location: location, name: clustername) }
    its('private_cluster_config.enable_private_nodes') { should cmp true }
  end
end

control "gke-4" do
  impact 1.0

  title "Ensure the GKE Control Plane is not public"

  desc "By default, the GKE Control Plane (Kubernetes API) is assigned a public IP address and the network access control allows access from `0.0.0.0/0`.  When a new vulnerability is found in the Kubernetes API server, the scope of potential attackers is the entire Internet.  By configuring the GKE Cluster with a private IP or by adding a restricted list of CIDRs with access to the API server, the scope is greatly limited and can buy valuable time to patch/upgrade.  Also, if credentials from in-cluster service accounts and Kubernetes components are leaked, they cannot be leveraged against the API server from any location."
  desc "remediation", "Recreate the GKE Cluster with the `--enable-private-endpoint` flag set.  If the cluster cannot be recreated with only a private IP, ensure that `--master-authorized-networks` is configured with a limited set of CIDR ranges."
  desc "validation", "Run `gcloud container clusters get` and review the `privateClusterConfig` configuration block. Ensure `enablePrivateEndpoint` is set to `true`.  Or, ensure the `masterAuthorizedNetworksConfig` configuration block has `cidrBlocks` that do not include `0.0.0.0/0`."

  tag platform: "GCP"
  tag category: "Network Access Control"
  tag resource: "GKE"
  tag effort: 0.2

  ref "GKE Private Control Plane", url: "https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters"
  ref "GKE Master Authorized Networks", url: "https://cloud.google.com/kubernetes-engine/docs/how-to/authorized-networks"

  cluster = google_container_regional_cluster(project: project_id, location: location, name: clustername)
  describe.one do
    describe "#{project_id}/#{location}/#{clustername}:" do
      subject { cluster } 
      its('private_cluster_config.enable_private_endpoint') { should cmp true }
      its('master_authorized_networks_config.cidr_blocks') { should_not be_empty }
    end
    describe "#{project_id}/#{location}/#{clustername}:" do
      subject { cluster } 
      its('master_authorized_networks_config.cidr_blocks') { should_not be_empty }
      its('master_authorized_networks_config.cidr_blocks.to_s') { should_not match /0.0.0.0\/0/ }
    end
  end
end

control "gke-5" do
  impact 0.9

  title "Ensure the GKE Cluster has the Network Policy managed addon enabled"

  desc "By default, all Kubernetes pods inside a cluster can communicate with each other--even across namespaces.  All production Kubernetes clusters should have support enabled for being able to define Layer 4 `NetworkPolicy` resources, and in many cases, this is an optional addon that must be explicitly enabled.  With this support enabled, it's possible to define policies inside the cluster that restrict inbound and outbound network traffic to pods within namespaces and provide micro-segmentation.  Should a pod become compromised, strict `NetworkPolicy` configurations can significantly limit the attacker's ability to move laterally via the network."
  desc "remediation", "During cluster creation, ensure the `--enable-network-policy` flag is configured.  For existing clusters, run `gcloud container clusters update cluster-name --update-addons=NetworkPolicy=ENABLED` followed by `gcloud container clusters update cluster-name --enable-network-policy`.  Note that this forces all nodepools to be recreated to have the CNI changes take effect."
  desc "validation", "Run `gcloud container clusters get` and review the `networkPolicy` configuration block. Ensure `provider` is set to `CALICO` and `enabled` is `true`."

  tag platform: "GCP"
  tag category: "Network Access Control"
  tag resource: "GKE"
  tag effort: 0.5

  ref "GKE Network Policy", url: "https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy#enabling_network_policy_enforcement"
  ref "Network Policy", url: "https://kubernetes.io/docs/concepts/services-networking/network-policies/#the-networkpolicy-resource"

  describe "#{project_id}/#{location}/#{clustername}:" do
    subject { google_container_regional_cluster(project: project_id, location: location, name: clustername) }
    its('network_policy.enabled') { should cmp true }
  end
end

control "gke-6" do
  impact 0.7

  title "Ensure GKE Cluster Nodepools are created with minimal OAuth Access Scopes and dedicated Service Accounts"

  desc "By default, GKE Cluster Nodepools are assigned the default Compute service account in the project, and this service account is bound to the `Project Editor` IAM Role which has wide-ranging permissions in the project across nearly all services.  However, these service account credentials bound to the GCE nodes that make up the GKE Nodepool can be further restricted by setting service-specific OAuth Scopes.  Unless additional network restrictions are place on pods running inside the cluster, this means that any pod in any namespace can obtain access to these instance credentials via the GCP Metadata API (169.254.169.254).  Before GKE 1.12, the OAuth Scopes commonly contained `compute` or even `cloud-platform`.  When combined with the `Project Editor` IAM Role, these instance credentials allow near full access to all `gcloud compute` commands or all gcloud services, respectively.  Since GKE 1.12, the scopes needed for proper management function are now a fixed list.  Pods wanting to gain access to credentials for accessing GCP APIs should use the Workload Identity feature to both block access to the instance credentials via the Metadata API and to map GCP Service Accounts to Kubernetes Service Accounts."
  desc "remediation", "Create a dedicated GCP Service Account.  Create and bind an IAM Role with `roles/monitoring.metricWriter`, `monitoring.viewer`, and `logging.logWriter` permissions to the dedicated GCP Service Account.  Specify that service account during Nodepool creation via the `--service-account` flag.  Recreation is necessary for existing nodepools."
  desc "validation", "Run `gcloud container clusters get` and review the `nodeConfig` configuration block. Ensure `serviceAccount` is not set to `default` and `oauthScopes` contains only `https://www.googleapis.com/auth/devstorage.read_only`, `logging.write`, `monitoring`, `service.management.readonly`, `servicecontrol`, and `trace.append`."

  tag platform: "GCP"
  tag category: "Identity and Access Management"
  tag resource: "GKE"
  tag effort: 0.2

  ref "GKE OAuth Access Scopes", url: "https://cloud.google.com/kubernetes-engine/docs/how-to/access-scopes"  
  ref "GCP Service Account Permissions", url: "https://cloud.google.com/compute/docs/access/service-accounts#service_account_permissions"
  ref "GCP Default Service Account", url: "https://cloud.google.com/compute/docs/access/service-accounts#default_service_account"

  google_container_regional_node_pools(project: project_id, location: location, cluster: clustername).names.each do |nodepool|
    describe "#{project_id}/#{location}/#{clustername}/#{nodepool}:" do
      subject { google_container_regional_node_pool(project: project_id, location: location, cluster: clustername, name: nodepool) }
      its('config.service_account') { should_not cmp "default" }
      its('config.oauth_scopes') { should_not include /cloud-platform/ }
      its('config.oauth_scopes') { should_not include /compute/ }
      its('config.oauth_scopes') { should_not include /compute-ro/ }
      its('config.oauth_scopes') { should_not include /compute-rw/ }
      its('config.oauth_scopes') { should_not include /container/ }
      its('config.oauth_scopes') { should_not include /iam/ }
      its('config.oauth_scopes') { should include /devstorage.read_only/ }
      its('config.oauth_scopes') { should include /logging.write/ }
      its('config.oauth_scopes') { should include /monitoring/ }
      its('config.oauth_scopes') { should include /service.management.readonly/ }
      its('config.oauth_scopes') { should include /servicecontrol/ }
      its('config.oauth_scopes') { should include /trace.append/ }
    end
  end
end
