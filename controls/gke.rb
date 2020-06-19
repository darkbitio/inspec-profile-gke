# frozen_string_literal: true

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

control 'gke-1' do
  impact 0.8

  title 'Ensure Stackdriver Logging and Monitoring is configured'
  desc 'default', <<~DESCRIPTION
Exporting logs and metrics to a dedicated, persistent datastore such as Stackdriver ensures availability of audit data following a cluster security event, and provides a central location for analysis of log and metric data collated from multiple sources.
DESCRIPTION

  desc 'remediation', <<~REMEDIATION
Ensure `--enable-stackdriver-kubernetes` is set during cluster configuration, or run `gcloud container clusters update` and pass the `--enable-stackdriver-kubernetes` flag to enable the addons.
REMEDIATION

  desc 'validation', <<~VALIDATION
Run `gcloud container clusters describe` and review the configuration under `loggingService` and `monitoringService`.  They should be configured with `logging.googleapis.com/kubernetes` and `monitoring.googleapis.com/kubernetes`, respectively.
VALIDATION

  tag platform: 'GCP'
  tag category: 'Logging and Monitoring'
  tag resource: 'GKE'
  tag effort: 0.2

  ref 'GKE Monitoring and Logging', url: 'https://cloud.google.com/monitoring/kubernetes-engine'

  describe "#{project_id}/#{location}/#{clustername}:" do
    subject { google_container_regional_cluster(project: project_id, location: location, name: clustername) }
    its('logging_service') { should match '/^logging.googleapis.com\/kubernetes/' }
    its('monitoring_service') { should match '/^monitoring.googleapis.com\/kubernetes/' }
  end
end

control 'gke-2' do
  impact 1.0

  title 'Ensure Basic Authentication is disabled'

  desc 'default', <<~DESCRIPTION
Until GKE 1.12, Basic Authentication was enabled by default on all clusters unless explicitly disabled.  Clusters that were created at or before version 1.12 and have been upgraded since will still have a valid username and password credential that grants full cluster access.  These credentials cannot be revoked or rotated without recreating the cluster.  Furthermore, they are available in clear-text via the `gcloud container clusters list/get` command, and many IAM Roles contain the `container.clusters.get` and `container.clusters.list` permissions, including `Project Viewer`.  When coupled with network access to the GKE API server, a clear path to become `cluster-admin` is possible.
DESCRIPTION

  desc 'remediation', <<~REMEDIATION
Recreate the GKE cluster from a recent version (1.12+) ensuring the `--no-enable-basic-auth` flag set or supply a <blank> value for the `master_auth.username` field when using Terraform.
REMEDIATION

  desc 'validation', <<~VALIDATION
Run `gcloud container clusters get` and review the `masterAuth` configuration block.  There should not be a `username` and `password` field with values.
VALIDATION

  tag platform: 'GCP'
  tag category: 'Identity and Access Management'
  tag resource: 'GKE'
  tag effort: 0.9

  ref 'Auth', url: 'https://cloud.google.com/kubernetes-engine/docs/how-to/iam-integration'

  describe "#{project_id}/#{location}/#{clustername}:" do
    subject { google_container_regional_cluster(project: project_id, location: location, name: clustername) }
    its('master_auth.username') { should cmp nil }
  end
end

control 'gke-3' do
  impact 0.5

  title 'Ensure GKE Nodes are not public'

  desc 'default', <<~DESCRIPTION
By default, GKE nodes are created with both private and public IP addresses assigned, and the default Firewall Rules in the default Network permit remote access via SSH on TCP/22 from `0.0.0.0/0`.  Preventing GKE Nodes from being assigned a public IP address ensures that remote access attempts using SSH cannot be routed from the public Internet.  Should a pod become compromised and escape to the underlying node, it's possible to use that access to add SSH credentials to the host configuration.  However, that node will not be directly accessible from the Internet for SSH access if a public IP is not assigned.
DESCRIPTION

  desc 'remediation', <<~REMEDIATION
Recreate the GKE cluster ensuring the `--enable-private-nodes` flag is configured.  Ensure administrators have another mechanism such as a Bastion Host in the same VPC or Cloud Identity-Aware Proxy access is available if SSH access is still required.
REMEDIATION

  desc 'validation', <<~VALIDATION
Run `gcloud container clusters get` and review the `privateClusterConfig` configuration block. Ensure `enablePrivateNodes` is set to `true`.
VALIDATION

  tag platform: 'GCP'
  tag category: 'Network Access Control'
  tag resource: 'GKE'
  tag effort: 0.9

  ref 'GKE Private Nodes', url: 'https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters'

  describe "#{project_id}/#{location}/#{clustername}:" do
    subject { google_container_regional_cluster(project: project_id, location: location, name: clustername) }
    its('private_cluster_config.enable_private_nodes') { should cmp true }
  end
end

control 'gke-4' do
  impact 1.0

  title 'Ensure the GKE Control Plane is not public'

  desc 'default', <<~DESCRIPTION
By default, the GKE Control Plane (Kubernetes API) is assigned a public IP address and the network access control allows access from `0.0.0.0/0`.  When a new vulnerability is found in the Kubernetes API server, the scope of potential attackers is the entire Internet.  By configuring the GKE Cluster with a private IP or by adding a restricted list of CIDRs with access to the API server, the scope is greatly limited and can buy valuable time to patch/upgrade.  Also, if credentials from in-cluster service accounts and Kubernetes components are leaked, they cannot be leveraged against the API server from any location.
DESCRIPTION

  desc 'remediation', <<~REMEDIATION
Recreate the GKE Cluster with the `--enable-private-endpoint` flag set.  If the cluster cannot be recreated with only a private IP, ensure that `--master-authorized-networks` is configured with a limited set of CIDR ranges.'
REMEDIATION

  desc 'validation', <<~VALIDATION
Run `gcloud container clusters get` and review the `privateClusterConfig` configuration block. Ensure `enablePrivateEndpoint` is set to `true`.  Or, ensure the `masterAuthorizedNetworksConfig` configuration block has `cidrBlocks` that do not include `0.0.0.0/0`.
VALIDATION

  tag platform: 'GCP'
  tag category: 'Network Access Control'
  tag resource: 'GKE'
  tag effort: 0.2

  ref 'GKE Private Control Plane', url: 'https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters'
  ref 'GKE Master Authorized Networks', url: 'https://cloud.google.com/kubernetes-engine/docs/how-to/authorized-networks'

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
      its('master_authorized_networks_config.cidr_blocks.to_s') { should_not match '/0.0.0.0\/0/' }
    end
  end
end

control 'gke-5' do
  impact 0.9

  title 'Ensure the GKE Cluster has the Network Policy managed addon enabled'

  desc 'default', <<~DESCRIPTION
By default, all Kubernetes pods inside a cluster can communicate with each other--even across namespaces.  All production Kubernetes clusters should have support enabled for being able to define Layer 4 `NetworkPolicy` resources, and in many cases, this is an optional addon that must be explicitly enabled.  With this support enabled, it's possible to define policies inside the cluster that restrict inbound and outbound network traffic to pods within namespaces and provide micro-segmentation.  Should a pod become compromised, strict `NetworkPolicy` configurations can significantly limit the attacker's ability to move laterally via the network.
DESCRIPTION

  desc 'remediation', <<~REMEDIATION
During cluster creation, ensure the `--enable-network-policy` flag is configured.  For existing clusters, run `gcloud container clusters update cluster-name --update-addons=NetworkPolicy=ENABLED` followed by `gcloud container clusters update cluster-name --enable-network-policy`.  Note that this forces all nodepools to be recreated to have the CNI changes take effect.
REMEDIATION

  desc 'validation', <<~VALIDATION
Run `gcloud container clusters get` and review the `networkPolicy` configuration block. Ensure `provider` is set to `CALICO` and `enabled` is `true`.
VALIDATION

  tag platform: 'GCP'
  tag category: 'Network Access Control'
  tag resource: 'GKE'
  tag effort: 0.5

  ref 'GKE Network Policy', url: 'https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy#enabling_network_policy_enforcement'
  ref 'Network Policy', url: 'https://kubernetes.io/docs/concepts/services-networking/network-policies/#the-networkpolicy-resource'

  describe "#{project_id}/#{location}/#{clustername}:" do
    subject { google_container_regional_cluster(project: project_id, location: location, name: clustername) }
    its('network_policy.enabled') { should cmp true }
  end
end

control 'gke-6' do
  impact 0.7

  title 'Ensure GKE Cluster Nodepools are created with minimal OAuth Access Scopes and dedicated Service Accounts'

  desc 'default', <<~DESCRIPTION
By default, GKE Cluster Nodepools are assigned the default Compute service account in the project, and this service account is bound to the `Project Editor` IAM Role which has wide-ranging permissions in the project across nearly all services.  However, these service account credentials bound to the GCE nodes that make up the GKE Nodepool can be further restricted by setting service-specific OAuth Scopes.  Unless additional network restrictions are place on pods running inside the cluster, this means that any pod in any namespace can obtain access to these instance credentials via the GCP Metadata API (169.254.169.254).  Before GKE 1.12, the OAuth Scopes commonly contained `compute` or even `cloud-platform`.  When combined with the `Project Editor` IAM Role, these instance credentials allow near full access to all `gcloud compute` commands or all gcloud services, respectively.  Since GKE 1.12, the scopes needed for proper management function are now a fixed list.  Pods wanting to gain access to credentials for accessing GCP APIs should use the Workload Identity feature to both block access to the instance credentials via the Metadata API and to map GCP Service Accounts to Kubernetes Service Accounts.
DESCRIPTION

  desc 'remediation', <<~REMEDIATION
Create a dedicated GCP Service Account.  Create and bind an IAM Role with `roles/monitoring.metricWriter`, `monitoring.viewer`, and `logging.logWriter` permissions to the dedicated GCP Service Account.  Specify that service account during Nodepool creation via the `--service-account` flag.  Recreation is necessary for existing nodepools.
REMEDIATION

  desc 'validation', <<~VALIDATION
Run `gcloud container clusters get` and review the `nodeConfig` configuration block. Ensure `serviceAccount` is not set to `default` and `oauthScopes` contains only `https://www.googleapis.com/auth/devstorage.read_only`, `logging.write`, `monitoring`, `service.management.readonly`, `servicecontrol`, and `trace.append`.
VALIDATION

  tag platform: 'GCP'
  tag category: 'Identity and Access Management'
  tag resource: 'GKE'
  tag effort: 0.2

  ref 'GKE OAuth Access Scopes', url: 'https://cloud.google.com/kubernetes-engine/docs/how-to/access-scopes'
  ref 'GCP Service Account Permissions', url: 'https://cloud.google.com/compute/docs/access/service-accounts#service_account_permissions'
  ref 'GCP Default Service Account', url: 'https://cloud.google.com/compute/docs/access/service-accounts#default_service_account'

  google_container_regional_node_pools(project: project_id, location: location, cluster: clustername).names.each do |nodepool|
    describe "#{project_id}/#{location}/#{clustername}/#{nodepool}:" do
      subject { google_container_regional_node_pool(project: project_id, location: location, cluster: clustername, name: nodepool) }
      its('config.service_account') { should_not cmp 'default' }
      its('config.oauth_scopes') { should_not include '/cloud-platform/' }
      its('config.oauth_scopes') { should_not include '/compute/' }
      its('config.oauth_scopes') { should_not include '/compute-ro/' }
      its('config.oauth_scopes') { should_not include '/compute-rw/' }
      its('config.oauth_scopes') { should_not include '/container/' }
      its('config.oauth_scopes') { should_not include '/iam/' }
      its('config.oauth_scopes') { should include '/devstorage.read_only/' }
      its('config.oauth_scopes') { should include '/logging.write/' }
      its('config.oauth_scopes') { should include '/monitoring/' }
      its('config.oauth_scopes') { should include '/service.management.readonly/' }
      its('config.oauth_scopes') { should include '/servicecontrol/' }
      its('config.oauth_scopes') { should include '/trace.append/' }
    end
  end
end

control 'gke-7' do
  impact 0.5

  title 'GKE Node Pools should use the COS or COS_CONTAINERD Operating System'

  desc 'default', <<~DESCRIPTION
GKE Nodes can leverage either Container-Optimized OS or Ubuntu-based operating system images.  Unless there is a very specific use-case that a Container-Optimized OS image cannot support such as installed certain drivers and/or kernel modules, Ubuntu nodes are not recommended.  Container-Optimized OS is a fully hardened operating system designed specifically to run containerized workloads with a high degree of security, and it receives automatic updates from Google.  The track record for security issues that affect Ubuntu nodes in GKE that did not affect COS nodes is also important to consider.
DESCRIPTION

  desc 'remediation', <<~REMEDIATION
Configure your GKE Node Pools to leverage either the COS or COS_CONTAINERD image type.  The COS image leverages Docker, and the COS_CONTAINERD image implements only containerd and does not use the commonly known Docker socket at `/var/run/docker.sock` which allows applications that can access that socket to effectively be `root` on the host.  If your workloads do not require the ability to mount the docker socket for activities such as image building in-cluster or certain security features, COS_CONTAINERD offers an even smaller attack surface than COS.  Considerations: changing the image type recreates the nodes in the node pool.
REMEDIATION

  desc 'validation', <<~VALIDATION
Run `gcloud container clusters describe <clustername> --format=json | jq -r 'select(.nodePools[].config.imageType | test("^COS")) | .name'` and ensure that the cluster's name is listed.
VALIDATION

  tag platform: 'GCP'
  tag category: 'Host and Cluster Security'
  tag resource: 'GKE'
  tag effort: 0.9

  ref 'GKE Node Images', url: 'https://cloud.google.com/kubernetes-engine/docs/concepts/node-images'

  google_container_regional_node_pools(project: project_id, location: location, cluster: clustername).names.each do |nodepool|
    describe "#{project_id}/#{location}/#{clustername}/#{nodepool}:" do
      subject { google_container_regional_node_pool(project: project_id, location: location, cluster: clustername, name: nodepool) }
      its('config.imageType') { should match '/^COS.*/i' }
    end
  end
end

control 'gke-8' do
  impact 0.9

  title 'GKE Workload Identity should be enabled and enforcing metadata protection on all NodePools'

  desc 'default', <<~DESCRIPTION
Currently, all pods have the ability to reach the Instance Metadata API corresponding to the underlying node.  By extension, those pods can access the APIs and data used to bootstrap the Kubernetes worker node.  The credentials used to bootstrap a Kubernetes worker node are very commonly sufficient to be used to privilege escalate to `cluster-admin`.  Also by extension, this means that every container image ever run in this cluster in the non-production namespace has had the ability to reach and export these credentials.  Therefore, it's very important for a cluster's security posture to prevent pods from being able to reach the Instance Metadata API to fetch those bootstrapping credentials.
DESCRIPTION

  desc 'remediation', <<~REMEDIATION
Configure Workload Identity on the cluster and every node pool in the cluster with the GKE_METADATA setting enabled.  Alternatively, deploy an egress NetworkPolicy blocking egress to 169.254.169.254 for all non-kube-system namespaces.
REMEDIATION

  desc 'validation', <<~VALIDATION
Run `gcloud container clusters describe <clustername> --format=json | jq -r 'select(.workloadIdentityConfig.workloadPool | test("svc.id.goog")) | .name'` and ensure that the cluster's name is listed.
VALIDATION

  tag platform: 'GCP'
  tag category: 'Host and Cluster Security'
  tag resource: 'GKE'
  tag effort: 0.5

  ref 'GKE Workload Identity', url: 'https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity'
  ref 'Hardening GKE', url: 'https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#workload_identity'

  describe "#{project_id}/#{location}/#{clustername}:" do
    subject { google_container_regional_cluster(project: project_id, location: location, name: clustername) }
    it 'should have workload identity configured at the cluster level' do
      expect(subject.config).to respond_to(:workloadIdentityConfig)
      expect(subject.config.workloadIdentityConfig).to respond_to(:workloadPool)
      expect(subject.config.workloadIdentityConfig.workloadPool).not_to be nil
    end
  end

  google_container_regional_node_pools(project: project_id, location: location, cluster: clustername).names.each do |nodepool|
    describe "#{project_id}/#{location}/#{clustername}/#{nodepool}:" do
      subject { google_container_regional_node_pool(project: project_id, location: location, cluster: clustername, name: nodepool) }
      it 'should have workload identity metadata server on the node pool' do
        expect(subject.config).to respond_to(:workloadMetadataConfig)
        expect(subject.config.workloadMetadataConfig).to respond_to(:mode)
        expect(subject.config.workloadMetadataConfig.mode).to eq('GKE_METADATA')
      end
    end
  end
end

control 'gke-9' do
  impact 0.9

  title 'Production GKE Clusters should have a highly-available control plane'

  desc 'default', <<~DESCRIPTION
By default, GKE creates a `zonal` cluster.  That is, a cluster where the single control plane GCE instance is deployed in one GCP availability zone.  GKE clusters can also be configured as `regional` clusters in which three control plane GCE instances can be deployed evenly across three availability zones at no direct, additional cost.  Having three control plane instances insulates from a single control plane instance failure and allows for zero-downtime API server upgrades.
DESCRIPTION

  desc 'remediation', <<~REMEDIATION
For all production GKE clusters, configure the `location` as the region name instead of the zone name.  This requires rebuilding the cluster if it is already deployed as a zonal cluster.
REMEDIATION

  desc 'validation', <<~VALIDATION
Run `gcloud container clusters describe <clustername> --format=json | jq -r 'select(.location | test("^[a-z]+-[a-z0-9]+$")) | .name'` and ensure that the cluster's name is listed.
VALIDATION

  tag platform: 'GCP'
  tag category: 'Operations and Response'
  tag resource: 'GKE'
  tag effort: 0.9

  ref 'GKE Regional Clusters', url: 'https://cloud.google.com/kubernetes-engine/docs/concepts/regional-clusters'

  describe "#{project_id}/#{location}/#{clustername}:" do
    subject { google_container_regional_cluster(project: project_id, location: location, name: clustername) }
    it 'should have a location that specifies a region' do
      expect(subject.config).to respond_to(:location)
      # want to match us-east4 for regional, not us-central1-a for zonal
      expect(subject.config.location).to match('/^\w+\-\w+$/')
    end
  end
end

control 'gke-8' do
  impact 0.5

  title 'GKE Shielded Nodes should be enabled on all NodePools'

  desc 'default', <<~DESCRIPTION
Starting in GKE 1.13.6 and later, GKE Worker nodes can be provisioned with a Virtual Trusted Platform Module (vTPM) that can be used to cryptographically verify the integrity of the boot process and to securely distribute the bootstrapping credentials used by the Kubelet to attach the node to the cluster on first boot.  Without this feature, the Kubelet's bootstrapping credentials are available via the GCE Metadata API, and that can be accessed by any Pod unless additional protections are put in place.  These credentials can be leveraged to escalate to cluster-admin in most situations.
DESCRIPTION

  desc 'remediation', <<~REMEDIATION
Modify the cluster node pool configuration to enable shielded nodes (--enable-shielded-nodes) and secure boot (--shielded-secure-boot).  This will remove the sensitive bootstrapping credentials from the GCE Metadata API and enable additional verification checks to ensure the worker nodes have not been compromised at a fundamental level.  Considerations: The nodes must be running the COS or COS_CONTAINERD operating system, and enabling this change will require a node pool rolling redeployment performed at the next maintenance window.
REMEDIATION

  desc 'validation', <<~VALIDATION
Run `gcloud container clusters describe <clustername> --format=json | jq -r 'select(.nodePools[].config.shieldedInstanceConfig.enableIntegrityMonitoring==true and .nodePools[].config.shieldedInstanceConfig.enableSecureBoot==true) | "\(.name)"'` and ensure that the cluster's name is listed.
VALIDATION

  tag platform: 'GCP'
  tag category: 'Host and Cluster Security'
  tag resource: 'GKE'
  tag effort: 0.5

  ref 'GKE Shielded Nodes', url: 'https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes'
  ref 'Hardening GKE', url: 'https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#shielded_nodes'

  google_container_regional_node_pools(project: project_id, location: location, cluster: clustername).names.each do |nodepool|
    describe "#{project_id}/#{location}/#{clustername}/#{nodepool}:" do
      subject { google_container_regional_node_pool(project: project_id, location: location, cluster: clustername, name: nodepool) }
      it 'should have workload identity metadata server on the node pool' do
        expect(subject.config).to respond_to(:shieldedInstanceConfig)
        expect(subject.config.shieldedInstanceConfig).to respond_to(:enableIntegrityMonitoring)
        expect(subject.config.shieldedInstanceConfig.enableIntegrityMonitoring).to eq(true)
      end
    end
  end
end
