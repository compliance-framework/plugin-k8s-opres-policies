package compliance_framework.k8s_az_coverage

import rego.v1

risk_templates := [
	{
		"name": "Application may be non-resilient due to insufficient multi-AZ or multi-region coverage",
		"title": "Application {{ .namespace }}/{{ .app_name }} may be non-resilient due to insufficient multi-AZ or multi-region coverage",
		"statement": "Application {{ .namespace }}/{{ .app_name }} is not distributed across the required availability zones or regions and may be unable to tolerate node, zone, or regional failures. Concentrating replicas in too few failure domains increases the likelihood of service disruption, degraded availability, and delayed recovery during infrastructure incidents or maintenance events.",
		"likelihood_hint": "moderate",
		"impact_hint": "high",
		"dedupe_label_keys": ["namespace", "app_name"],
		"label_schema": [
			{
				"key": "namespace",
				"description": "Kubernetes namespace containing the application"
			},
			{
				"key": "app_name",
				"description": "Logical application name derived from workload identity labels"
			}
		],
		"threat_refs": [
			{
				"system": "https://cwe.mitre.org",
				"external_id": "CWE-693",
				"title": "Protection Mechanism Failure",
				"url": "https://cwe.mitre.org/data/definitions/693.html"
			}
		],
		"remediation": {
			"title": "Distribute application replicas across independent failure domains",
			"description": "Update workload scheduling and capacity so the application spans the required availability zones and, where required, regions. Ensure node labels, topology constraints, anti-affinity rules, and cluster capacity all support resilient placement.",
			"tasks": [
				{"title": "Configure topology spread constraints or pod anti-affinity so replicas are distributed across availability zones"},
				{"title": "Verify each target cluster has schedulable capacity in every required availability zone"},
				{"title": "Ensure nodes are labeled consistently with topology.kubernetes.io/zone and topology.kubernetes.io/region"},
				{"title": "Deploy the application into additional clusters or regions when regional resilience requirements apply"},
				{"title": "Validate failover behavior by testing zone or regional disruption scenarios"}
			]
		}
	}
]

# --- Configuration from policy_input ---

_expected_azs := object.get(input, "expected_azs", [])

_expected_regions := object.get(input, "expected_regions", [])

_min_azs := object.get(input, "min_azs", 0)

_min_regions := object.get(input, "min_regions", 0)

_app_label := object.get(input, "app_label", "app.kubernetes.io/name")

_clusters := object.get(object.get(input, "fleet", {}), "clusters", {})

_subject := object.get(input, "subject", {})

_current_namespace := object.get(_subject, "namespace", _resource_namespace(object.get(input, "main", {})))

# --- Helpers ---

_resource_namespace(resource) := object.get(object.get(resource, "metadata", {}), "namespace", "default")

_resource_name(resource) := object.get(object.get(resource, "metadata", {}), "name", "")

_resource_label_value(resource, key) := value if {
	labels := object.get(object.get(resource, "metadata", {}), "labels", {})
	value := object.get(labels, key, "")
	value != ""
}

_resource_label_value(resource, key) := value if {
	not _resource_metadata_label_value(resource, key)
	spec := object.get(resource, "spec", {})
	template := object.get(spec, "template", {})
	template_meta := object.get(template, "metadata", {})
	labels := object.get(template_meta, "labels", {})
	value := object.get(labels, key, "")
	value != ""
}

_resource_label_value(resource, key) := value if {
	not _resource_metadata_label_value(resource, key)
	not _resource_template_label_value(resource, key)
	spec := object.get(resource, "spec", {})
	selector := object.get(spec, "selector", {})
	labels := object.get(selector, "matchLabels", {})
	value := object.get(labels, key, "")
	value != ""
}


_resource_metadata_label_value(resource, key) if {
	labels := object.get(object.get(resource, "metadata", {}), "labels", {})
	object.get(labels, key, "") != ""
}

_resource_template_label_value(resource, key) if {
	spec := object.get(resource, "spec", {})
	template := object.get(spec, "template", {})
	template_meta := object.get(template, "metadata", {})
	labels := object.get(template_meta, "labels", {})
	object.get(labels, key, "") != ""
}

_current_app_name := app_name if {
	app_name := _resource_label_value(object.get(input, "main", {}), _app_label)
	app_name != ""
}

_current_app_name := app_name if {
	not _resource_label_value(object.get(input, "main", {}), _app_label)
	identity_labels := object.get(_subject, "identity_labels", {})
	app_name := object.get(identity_labels, "app_name", "")
	app_name != ""
}

_current_app_name := app_name if {
	not _resource_label_value(object.get(input, "main", {}), _app_label)
	identity_labels := object.get(_subject, "identity_labels", {})
	object.get(identity_labels, "app_name", "") == ""
	app_name := _resource_name(object.get(input, "main", {}))
	app_name != ""
}

_evaluated_app_id := _global_app_id(_current_namespace, _current_app_name)

_global_app_id(namespace, app_name) := sprintf("%s/%s", [namespace, app_name])

_selector_has_requirements(resource) if {
	selector := object.get(object.get(resource, "spec", {}), "selector", {})
	count(object.keys(object.get(selector, "matchLabels", {}))) > 0
}

_selector_has_requirements(resource) if {
	selector := object.get(object.get(resource, "spec", {}), "selector", {})
	count(object.get(selector, "matchExpressions", [])) > 0
}

_selector_match_expression_matches_pod(expr, pod) if {
	operator := object.get(expr, "operator", "")
	operator == "In"
	key := object.get(expr, "key", "")
	key != ""
	values := object.get(expr, "values", [])
	pod_labels := object.get(object.get(pod, "metadata", {}), "labels", {})
	pod_value := object.get(pod_labels, key, null)
	pod_value != null
	pod_value in values
}

_selector_match_expression_matches_pod(expr, pod) if {
	operator := object.get(expr, "operator", "")
	operator == "NotIn"
	key := object.get(expr, "key", "")
	key != ""
	values := object.get(expr, "values", [])
	pod_labels := object.get(object.get(pod, "metadata", {}), "labels", {})
	pod_value := object.get(pod_labels, key, null)
	pod_value != null
	not pod_value in values
}

_selector_match_expression_matches_pod(expr, pod) if {
	operator := object.get(expr, "operator", "")
	operator == "Exists"
	key := object.get(expr, "key", "")
	key != ""
	pod_labels := object.get(object.get(pod, "metadata", {}), "labels", {})
	object.get(pod_labels, key, null) != null
}

_selector_match_expression_matches_pod(expr, pod) if {
	operator := object.get(expr, "operator", "")
	operator == "DoesNotExist"
	key := object.get(expr, "key", "")
	key != ""
	pod_labels := object.get(object.get(pod, "metadata", {}), "labels", {})
	object.get(pod_labels, key, null) == null
}

_selector_matches_pod(resource, pod) if {
	selector := object.get(object.get(resource, "spec", {}), "selector", {})
	_selector_has_requirements(resource)
	match_labels := object.get(selector, "matchLabels", {})
	match_expressions := object.get(selector, "matchExpressions", [])
	pod_labels := object.get(object.get(pod, "metadata", {}), "labels", {})
	every key, value in match_labels {
		object.get(pod_labels, key, "") == value
	}
	every expr in match_expressions {
		_selector_match_expression_matches_pod(expr, pod)
	}
}

# Per-cluster: node_name → AZ (current label)
_node_az[cluster_name][node_name] := az if {
	some cluster_name, cluster in _clusters
	some node in object.get(object.get(cluster, "resources", {}), "nodes", [])
	node_name := node.metadata.name
	labels := object.get(object.get(node, "metadata", {}), "labels", {})
	az := object.get(labels, "topology.kubernetes.io/zone", "")
	az != ""
}

# Per-cluster: node_name → AZ (legacy label fallback)
_node_az[cluster_name][node_name] := az if {
	some cluster_name, cluster in _clusters
	some node in object.get(object.get(cluster, "resources", {}), "nodes", [])
	node_name := node.metadata.name
	labels := object.get(object.get(node, "metadata", {}), "labels", {})
	not labels["topology.kubernetes.io/zone"]
	az := object.get(labels, "failure-domain.beta.kubernetes.io/zone", "")
	az != ""
}

# Per-cluster: region for a given cluster
_cluster_region[cluster_name] := region if {
	some cluster_name, cluster in _clusters
	cluster_info := object.get(cluster, "cluster", {})
	region := object.get(cluster_info, "region", "")
	region != ""
}

_cluster_region[cluster_name] := region if {
	some cluster_name, cluster in _clusters
	cluster_info := object.get(cluster, "cluster", {})
	object.get(cluster_info, "region", "") == ""
	some node in object.get(object.get(cluster, "resources", {}), "nodes", [])
	labels := object.get(object.get(node, "metadata", {}), "labels", {})
	region := object.get(labels, "topology.kubernetes.io/region", "")
	region != ""
}

_cluster_region[cluster_name] := region if {
	some cluster_name, cluster in _clusters
	cluster_info := object.get(cluster, "cluster", {})
	object.get(cluster_info, "region", "") == ""
	some node in object.get(object.get(cluster, "resources", {}), "nodes", [])
	labels := object.get(object.get(node, "metadata", {}), "labels", {})
	not labels["topology.kubernetes.io/region"]
	region := object.get(labels, "failure-domain.beta.kubernetes.io/region", "")
	region != ""
}

# Per-cluster current app tracking for pod-level checks
_cluster_app_pods[cluster_name] contains pod if {
	some cluster_name, cluster in _clusters
	some pod in object.get(object.get(cluster, "resources", {}), "pods", [])
	_resource_namespace(pod) == _current_namespace
	_selector_matches_pod(object.get(input, "main", {}), pod)
}

_cluster_app_pods[cluster_name] contains pod if {
	some cluster_name, cluster in _clusters
	some pod in object.get(object.get(cluster, "resources", {}), "pods", [])
	_resource_namespace(pod) == _current_namespace
	not _selector_has_requirements(object.get(input, "main", {}))
	_resource_label_value(pod, _app_label) == _current_app_name
}

# Current app placements across the fleet
_app_placements contains {"cluster": cluster_name, "node": node_name} if {
	some cluster_name, pods in _cluster_app_pods
	some pod in pods
	node_name := object.get(object.get(pod, "spec", {}), "nodeName", "")
	node_name != ""
	_ = _node_az[cluster_name][node_name]
}

# Current app AZs across the fleet
_current_app_azs := {az |
	some placement in _app_placements
	az := _node_az[placement.cluster][placement.node]
}

# Current app regions across the fleet
_current_app_regions := {region |
	some cluster_name, pods in _cluster_app_pods
	count(pods) > 0
	region := _cluster_region[cluster_name]
}

_current_app_az_list := sort([az | some az in _current_app_azs])

_current_app_region_list := sort([region | some region in _current_app_regions])

_format_seen_count(n) := "seen once" if {
	n == 1
}

_format_seen_count(n) := "seen twice" if {
	n == 2
}

_format_seen_count(n) := sprintf("seen %d times", [n]) if {
	n > 2
}

_current_app_az_counts[az] := count([1 |
	some cluster_name, pods in _cluster_app_pods
	some pod in pods
	node_name := object.get(object.get(pod, "spec", {}), "nodeName", "")
	node_name != ""
	_node_az[cluster_name][node_name] == az
]) if {
	some az in _current_app_azs
}

_current_app_region_counts[region] := count([1 |
	some cluster_name, pods in _cluster_app_pods
	count(pods) > 0
	_cluster_region[cluster_name] == region
]) if {
	some region in _current_app_regions
}

_current_app_az_count_list := sort([sprintf("%s - %s", [az, _format_seen_count(_current_app_az_counts[az])]) |
	some az in _current_app_azs
])

_current_app_region_count_list := sort([sprintf("%s - %s", [region, _format_seen_count(_current_app_region_counts[region])]) |
	some region in _current_app_regions
])

_current_app_az_count_summary := concat(", ", _current_app_az_count_list) if {
	count(_current_app_az_count_list) > 0
}

_current_app_az_count_summary := "none observed" if {
	count(_current_app_az_count_list) == 0
}

_current_app_region_count_summary := concat(", ", _current_app_region_count_list) if {
	count(_current_app_region_count_list) > 0
}

_current_app_region_count_summary := "none observed" if {
	count(_current_app_region_count_list) == 0
}

_missing_expected_azs := sort([az |
	some az in _expected_azs
	not az in _current_app_azs
])

_missing_expected_regions := sort([region |
	some region in _expected_regions
	not region in _current_app_regions
])

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

# Violation: current app missing from an explicitly required AZ
violation[{"remarks": msg}] if {
	count(_expected_azs) > 0
	some az in _missing_expected_azs
	msg := sprintf("App %q has no pods in required AZ %s across any cluster (current AZs: %s)", [_evaluated_app_id, az, _current_app_az_count_summary])
}

# Violation: current app missing from an explicitly required region
violation[{"remarks": msg}] if {
	count(_expected_regions) > 0
	some region in _missing_expected_regions
	msg := sprintf("App %q has no pods in required region %s across any cluster (current regions: %s)", [_evaluated_app_id, region, _current_app_region_count_summary])
}

# Violation: current app does not meet minimum AZ count
violation[{"remarks": msg}] if {
	_min_azs > 0
	count(_current_app_azs) < _min_azs
	msg := sprintf("App %q spans only %d AZ(s) across all clusters (current AZs: %s), minimum required is %d", [_evaluated_app_id, count(_current_app_azs), _current_app_az_count_summary, _min_azs])
}

# Violation: current app does not meet minimum region count
violation[{"remarks": msg}] if {
	_min_regions > 0
	count(_current_app_regions) < _min_regions
	msg := sprintf("App %q spans only %d region(s) across all clusters (current regions: %s), minimum required is %d", [_evaluated_app_id, count(_current_app_regions), _current_app_region_count_summary, _min_regions])
}

# Violation: pod on a node with no AZ label
violation[{"remarks": msg}] if {
	some cluster_name, pods in _cluster_app_pods
	some pod in pods
	node_name := object.get(object.get(pod, "spec", {}), "nodeName", "")
	node_name != ""
	not _node_az[cluster_name][node_name]
	msg := sprintf("Cluster %q: pod %q (app=%s) on node %q has no AZ label",
		[cluster_name, pod.metadata.name, _evaluated_app_id, node_name])
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

# Current app failing expected_azs check
_failed_apps_expected_azs := {_evaluated_app_id |
	count(_expected_azs) > 0
	count(_missing_expected_azs) > 0
}

# Current app failing expected_regions check
_failed_apps_expected_regions := {_evaluated_app_id |
	count(_expected_regions) > 0
	count(_missing_expected_regions) > 0
}

# Current app failing min_azs check
_failed_apps_min_azs := {_evaluated_app_id |
	_min_azs > 0
	count(_current_app_azs) < _min_azs
}

# Current app failing min_regions check
_failed_apps_min_regions := {_evaluated_app_id |
	_min_regions > 0
	count(_current_app_regions) < _min_regions
}

# Union of all failed apps across all criteria
_failed_apps := _failed_apps_expected_azs | _failed_apps_expected_regions | _failed_apps_min_azs | _failed_apps_min_regions

# Build detailed failure list
_failure_details := concat("\n", [msg |
	some app_id in _failed_apps
	az_parts := [s | count(_missing_expected_azs) > 0; s := sprintf("missing required AZs: %s (current AZs: %s)", [concat(", ", _missing_expected_azs), _current_app_az_count_summary])]
	region_parts := [s | count(_missing_expected_regions) > 0; s := sprintf("missing required regions: %s (current regions: %s)", [concat(", ", _missing_expected_regions), _current_app_region_count_summary])]
	min_az_parts := [s | _min_azs > 0; count(_current_app_azs) < _min_azs; s := sprintf("only %d/%d AZs (current AZs: %s)", [count(_current_app_azs), _min_azs, _current_app_az_count_summary])]
	min_region_parts := [s | _min_regions > 0; count(_current_app_regions) < _min_regions; s := sprintf("only %d/%d regions (current regions: %s)", [count(_current_app_regions), _min_regions, _current_app_region_count_summary])]
	parts := array.concat(array.concat(array.concat(az_parts, region_parts), min_az_parts), min_region_parts)
	count(parts) > 0
	msg := sprintf("  %s = %s", [app_id, concat("; ", parts)])
])

_failed_check_count := count([1 | count(_missing_expected_azs) > 0]) + count([1 | count(_missing_expected_regions) > 0]) + count([1 | _min_azs > 0; count(_current_app_azs) < _min_azs]) + count([1 | _min_regions > 0; count(_current_app_regions) < _min_regions])

title := sprintf("AZ checks for k8s deployment %s/%s/%s", [object.get(_subject, "cluster_name", object.get(object.get(object.get(input, "context", {}), "cluster", {}), "name", "")), _current_namespace, _resource_name(object.get(input, "main", {}))])

description := sprintf("Evaluated AZ/region coverage for deployment %q across %d cluster(s).\nFailed checks: %d",
	[_evaluated_app_id, count(_clusters), _failed_check_count]) if {
	count(_failed_apps) == 0
}

description := concat("", [
	sprintf("Evaluated AZ/region coverage for deployment %q across %d cluster(s).\n", [_evaluated_app_id, count(_clusters)]),
	sprintf("Failed checks: %d\n", [_failed_check_count]),
	_failure_details,
]) if {
	count(_failed_apps) > 0
}
