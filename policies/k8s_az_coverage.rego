package compliance_framework.k8s_az_coverage

import rego.v1

# --- Configuration from policy_input ---

_expected_azs := object.get(input, "expected_azs", [])

_expected_regions := object.get(input, "expected_regions", [])

_min_azs := object.get(input, "min_azs", 0)

_min_regions := object.get(input, "min_regions", 0)

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

# Per-cluster: region for a given cluster
_cluster_region[cluster_name] := region if {
	some cluster_name, cluster in _clusters
	region := object.get(cluster, "region", "")
	region != ""
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

# Global apps: app_id → set of regions where the app has running pods across ALL clusters
_global_app_regions[app_id] := regions if {
	some cluster_name, cluster in _clusters
	pods := object.get(object.get(cluster, "resources", {}), "pods", [])
	some pod in pods
	app_name := object.get(object.get(pod.metadata, "labels", {}), _app_label, "")
	app_name != ""
	namespace := object.get(object.get(pod, "metadata", {}), "namespace", "default")
	app_id := _global_app_id(namespace, app_name)
	regions := {region |
		some cn, c in _clusters
		some p in object.get(object.get(c, "resources", {}), "pods", [])
		object.get(object.get(p.metadata, "labels", {}), _app_label, "") == app_name
		object.get(object.get(p, "metadata", {}), "namespace", "default") == namespace
		node_name := object.get(object.get(p, "spec", {}), "nodeName", "")
		node_name != ""
		_ = _node_az[cn][node_name]
		region := _cluster_region[cn]
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

# True when at least one compliance criterion is configured
_has_criteria if {
	count(_expected_azs) > 0
}

_has_criteria if {
	count(_expected_regions) > 0
}

_has_criteria if {
	_min_azs > 0
}

_has_criteria if {
	_min_regions > 0
}

# --- Violations ---

# Violation: global app missing from an explicitly required AZ
violation[{"remarks": msg}] if {
	count(_expected_azs) > 0
	some app_id, azs in _global_app_azs
	some az in _expected_azs
	not az in azs
	msg := sprintf("App %q has no pods in required AZ %s across any cluster", [app_id, az])
}

# Violation: global app missing from an explicitly required region
violation[{"remarks": msg}] if {
	count(_expected_regions) > 0
	some app_id, regions in _global_app_regions
	some region in _expected_regions
	not region in regions
	msg := sprintf("App %q has no pods in required region %s across any cluster", [app_id, region])
}

# Violation: global app does not meet minimum AZ count
violation[{"remarks": msg}] if {
	_min_azs > 0
	some app_id, azs in _global_app_azs
	count(azs) < _min_azs
	msg := sprintf("App %q spans only %d AZ(s) across all clusters, minimum required is %d", [app_id, count(azs), _min_azs])
}

# Violation: global app does not meet minimum region count
violation[{"remarks": msg}] if {
	_min_regions > 0
	some app_id, regions in _global_app_regions
	count(regions) < _min_regions
	msg := sprintf("App %q spans only %d region(s) across all clusters, minimum required is %d", [app_id, count(regions), _min_regions])
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

# Violation: no compliance criteria configured
violation[{"remarks": "No compliance criteria configured in policy_input (expected_azs, expected_regions, min_azs, or min_regions)"}] if {
	count(_clusters) > 0
	not _has_criteria
}

# Violation: empty cluster data
violation[{"remarks": "No cluster data available"}] if {
	count(_clusters) == 0
}

# --- Metadata ---

# Apps failing expected_azs check
_failed_apps_expected_azs := {app_id |
	count(_expected_azs) > 0
	some app_id, azs in _global_app_azs
	some az in _expected_azs
	not az in azs
}

# Apps failing expected_regions check
_failed_apps_expected_regions := {app_id |
	count(_expected_regions) > 0
	some app_id, regions in _global_app_regions
	some region in _expected_regions
	not region in regions
}

# Apps failing min_azs check
_failed_apps_min_azs := {app_id |
	_min_azs > 0
	some app_id, azs in _global_app_azs
	count(azs) < _min_azs
}

# Apps failing min_regions check
_failed_apps_min_regions := {app_id |
	_min_regions > 0
	some app_id, regions in _global_app_regions
	count(regions) < _min_regions
}

# Union of all failed apps across all criteria
_failed_apps := _failed_apps_expected_azs | _failed_apps_expected_regions | _failed_apps_min_azs | _failed_apps_min_regions

# Build detailed failure list
_failure_details := concat("\n", [msg |
	some app_id in _failed_apps
	azs := object.get(_global_app_azs, app_id, {})
	regions := object.get(_global_app_regions, app_id, {})
	missing_azs := [az | some az in _expected_azs; not az in azs]
	missing_regions := [r | some r in _expected_regions; not r in regions]
	az_parts := [s | count(missing_azs) > 0; s := sprintf("missing required AZs: %s", [concat(", ", missing_azs)])]
	region_parts := [s | count(missing_regions) > 0; s := sprintf("missing required regions: %s", [concat(", ", missing_regions)])]
	min_az_parts := [s | _min_azs > 0; count(azs) < _min_azs; s := sprintf("only %d/%d AZs", [count(azs), _min_azs])]
	min_region_parts := [s | _min_regions > 0; count(regions) < _min_regions; s := sprintf("only %d/%d regions", [count(regions), _min_regions])]
	parts := array.concat(array.concat(array.concat(az_parts, region_parts), min_az_parts), min_region_parts)
	count(parts) > 0
	msg := sprintf("  %s = %s", [app_id, concat("; ", parts)])
])

title := "Kubernetes AZ Coverage Check"

description := sprintf("Evaluated AZ/region coverage across %d cluster(s).\nFailed apps: %d",
	[count(_clusters), count(_failed_apps)]) if {
	count(_failed_apps) == 0
}

description := concat("", [
	sprintf("Evaluated AZ/region coverage across %d cluster(s).\n", [count(_clusters)]),
	sprintf("Failed apps: %d\n", [count(_failed_apps)]),
	_failure_details,
]) if {
	count(_failed_apps) > 0
}
