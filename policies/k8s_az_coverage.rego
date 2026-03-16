package compliance_framework.k8s_az_coverage

import rego.v1

# --- Configuration from policy_input ---

_expected_azs := object.get(input, "expected_azs", [])

_app_label := object.get(input, "app_label", "app.kubernetes.io/name")

_clusters := object.get(input, "clusters", {})

# --- Helpers ---

# Per-cluster: node_name → AZ (current label)
_node_az[cluster_name][node_name] := az if {
	some cluster_name, cluster in _clusters
	some node in object.get(object.get(cluster, "resources", {}), "nodes", [])
	node_name := node.metadata.name
	labels := object.get(object.get(node, "metadata", {}), "labels", {})
	az := labels["topology.kubernetes.io/zone"]
}

# Per-cluster: node_name → AZ (legacy label fallback)
_node_az[cluster_name][node_name] := az if {
	some cluster_name, cluster in _clusters
	some node in object.get(object.get(cluster, "resources", {}), "nodes", [])
	node_name := node.metadata.name
	labels := object.get(object.get(node, "metadata", {}), "labels", {})
	not labels["topology.kubernetes.io/zone"]
	az := labels["failure-domain.beta.kubernetes.io/zone"]
}

# Global app identifier: namespace + app_label value
_global_app_id(namespace, app_name) := sprintf("%s/%s", [namespace, app_name])

# Global apps: app_id → set of AZs where the app has running pods across ALL clusters
_global_app_azs[app_id] := azs if {
	some cluster_name, cluster in _clusters
	pods := object.get(object.get(cluster, "resources", {}), "pods", [])
	some pod in pods
	app_name := object.get(object.get(pod.metadata, "labels", {}), _app_label, "")
	app_name != ""
	namespace := object.get(object.get(pod, "metadata", {}), "namespace", "default")
	app_id := _global_app_id(namespace, app_name)
	azs := {az |
		some cn, c in _clusters
		some p in object.get(object.get(c, "resources", {}), "pods", [])
		object.get(object.get(p.metadata, "labels", {}), _app_label, "") == app_name
		object.get(object.get(p, "metadata", {}), "namespace", "default") == namespace
		node_name := object.get(object.get(p, "spec", {}), "nodeName", "")
		node_name != ""
		az := _node_az[cn][node_name]
	}
}

# Per-cluster app tracking for pod-level violations
_cluster_app_pods[cluster_name][app_id] contains pod if {
	some cluster_name, cluster in _clusters
	some pod in object.get(object.get(cluster, "resources", {}), "pods", [])
	app_name := object.get(object.get(pod.metadata, "labels", {}), _app_label, "")
	app_name != ""
	namespace := object.get(object.get(pod, "metadata", {}), "namespace", "default")
	app_id := _global_app_id(namespace, app_name)
}

# --- Violations ---

# Violation: global app missing from an expected AZ across all clusters
violation[{"remarks": msg}] if {
	count(_expected_azs) > 0
	some app_id, azs in _global_app_azs
	some az in _expected_azs
	not az in azs
	msg := sprintf("App %q has no pods in AZ %s across any cluster", [app_id, az])
}

# Violation: pod on a node with no AZ label
violation[{"remarks": msg}] if {
	some cluster_name, cluster in _clusters
	some pod in object.get(object.get(cluster, "resources", {}), "pods", [])
	app_name := object.get(object.get(pod.metadata, "labels", {}), _app_label, "")
	app_name != ""
	namespace := object.get(object.get(pod, "metadata", {}), "namespace", "default")
	node_name := object.get(object.get(pod, "spec", {}), "nodeName", "")
	node_name != ""
	not _node_az[cluster_name][node_name]
	app_id := _global_app_id(namespace, app_name)
	msg := sprintf("Cluster %q: pod %q (app=%s) on node %q has no AZ label",
		[cluster_name, pod.metadata.name, app_id, node_name])
}

# Violation: no expected_azs configured
violation[{"remarks": "No expected_azs configured in policy_input"}] if {
	count(_expected_azs) == 0
}

# Violation: empty cluster data
violation[{"remarks": "No cluster data available"}] if {
	count(_clusters) == 0
}

# --- Metadata ---

# Count of apps with AZ coverage violations
_failed_apps := {app_id |
	count(_expected_azs) > 0
	some app_id, azs in _global_app_azs
	some az in _expected_azs
	not az in azs
}

# Build detailed failure list
_failure_details := concat("\n", [msg |
	count(_expected_azs) > 0
	some app_id, azs in _global_app_azs
	missing_azs := [az | some az in _expected_azs; not az in azs]
	count(missing_azs) > 0
	msg := sprintf("  %s = missing AZs: %s", [app_id, concat(", ", missing_azs)])
])

title := "Kubernetes AZ Coverage Check"

description := sprintf("Evaluated AZ coverage across %d cluster(s) for expected AZs: %v.\nFailed apps: %d",
	[count(_clusters), _expected_azs, count(_failed_apps)]) if {
	count(_failed_apps) == 0
}

description := concat("", [
	sprintf("Evaluated AZ coverage across %d cluster(s) for expected AZs: %v.\n", [count(_clusters), _expected_azs]),
	sprintf("Failed apps: %d\n", [count(_failed_apps)]),
	_failure_details,
]) if {
	count(_failed_apps) > 0
}
