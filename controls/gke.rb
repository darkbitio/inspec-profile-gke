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
  desc "descripton"
  desc "remediation", "remediation"

  tag domain: "01. Identity and Access Management"
  tag platform: "GCP"
  tag category: "Identity and Access Management"
  tag resource: "GCP"
  tag effort: 0.2

  ref "Stackdriver", url: "https://cloud.google.com/kubernetes-engine/docs/how-to/logging"

  describe "#{project_id}/#{location}/#{clustername}:" do
    subject { google_container_regional_cluster(project: project_id, location: location, name: clustername) }
    its('logging_service') { should match /^logging.googleapis.com\/kubernetes/ }
    its('monitoring_service') { should match /^monitoring.googleapis.com\/kubernetes/ }
  end
end

control "gke-2" do
  impact 1.0

  title "Ensure Legacy ABAC is disabled"
  desc "descripton"
  desc "remediation", "remediation"

  tag domain: "01. Identity and Access Management"
  tag platform: "GCP"
  tag category: "Identity and Access Management"
  tag resource: "GCP"
  tag effort: 0.2

  ref "RBAC", url: "https://cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control"

  describe "#{project_id}/#{location}/#{clustername}:" do
    subject { google_container_regional_cluster(project: project_id, location: location, name: clustername) }
    its('legacy_abac.enabled') { should cmp nil }
  end
end

control "gke-3" do
  impact 0.9

  title "Ensure Master authorized networks is configured"
  desc "descripton"
  desc "remediation", "remediation"

  tag domain: "01. Identity and Access Management"
  tag platform: "GCP"
  tag category: "Identity and Access Management"
  tag resource: "GCP"
  tag effort: 0.2

  ref "MAN", url: "https://cloud.google.com/kubernetes-engine/docs/how-to/authorized-networks"

  describe "#{project_id}/#{location}/#{clustername}:" do
    subject { google_container_regional_cluster(project: project_id, location: location, name: clustername) }
    its('master_authorized_networks_config.cidr_blocks') { should_not be_empty }
    its('master_authorized_networks_config.cidr_blocks.to_s') { should_not match /0.0.0.0\/0/ }
  end
end

control "gke-4" do
  impact 0.8

  title "Ensure Basic Authentication is disabled"
  desc "descripton"
  desc "remediation", "remediation"

  tag domain: "01. Identity and Access Management"
  tag platform: "GCP"
  tag category: "Identity and Access Management"
  tag resource: "GCP"
  tag effort: 0.2

  ref "Auth", url: "https://cloud.google.com/kubernetes-engine/docs/how-to/iam-integration"

  describe "#{project_id}/#{location}/#{clustername}:" do
    subject { google_container_regional_cluster(project: project_id, location: location, name: clustername) }
    its('master_auth.username') { should cmp nil }
  end
end

control "gke-5" do
  impact 0.8

  title "Ensure Network policy is enabled"
  desc "descripton"
  desc "remediation", "remediation"

  tag domain: "01. Identity and Access Management"
  tag platform: "GCP"
  tag category: "Identity and Access Management"
  tag resource: "GCP"
  tag effort: 0.2

  ref "Network Policy", url: "https://kubernetes.io/docs/concepts/services-networking/network-policies/#the-networkpolicy-resource"

  describe "#{project_id}/#{location}/#{clustername}:" do
    subject { google_container_regional_cluster(project: project_id, location: location, name: clustername) }
    its('network_policy.enabled') { should cmp true }
  end
end

control "gke-6" do
  impact 0.7

  title "Ensure Kubernetes Clusters created with limited service account Access scopes"
  desc "descripton"
  desc "remediation", "remediation"

  tag domain: "01. Identity and Access Management"
  tag platform: "GCP"
  tag category: "Identity and Access Management"
  tag resource: "GCP"
  tag effort: 0.2

  ref "OAuth Scopes", url: "https://cloud.google.com/compute/docs/access/service-accounts#the_default_service_account"

  google_container_regional_node_pools(project: project_id, location: location, cluster: clustername).names.each do |nodepool|
    describe "#{project_id}/#{location}/#{clustername}/#{nodepool}:" do
      subject { google_container_regional_node_pool(project: project_id, location: location, cluster: clustername, name: nodepool) }
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

control "gke-7" do
  impact 0.6

  title "Ensure a private cluster"
  desc "descripton"
  desc "remediation", "remediation"

  tag domain: "01. Identity and Access Management"
  tag platform: "GCP"
  tag category: "Identity and Access Management"
  tag resource: "GCP"
  tag effort: 0.2

  ref "Private", url: "https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters"

  describe "#{project_id}/#{location}/#{clustername}:" do
    subject { google_container_regional_cluster(project: project_id, location: location, name: clustername) }
    its('private_cluster_config.enable_private_endpoint') { should cmp true }
    its('private_cluster_config.enable_private_nodes') { should cmp true }
  end
end
