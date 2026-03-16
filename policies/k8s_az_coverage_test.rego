package compliance_framework.k8s_az_coverage_test

import data.compliance_framework.k8s_az_coverage
import rego.v1

# --- Helpers ---

_base_fixture(cluster_nodes, cluster_pods) := {
	"expected_azs": ["us-east-1a", "us-east-1b", "us-east-1c"],
	"clusters": {"prod": {
		"name": "prod",
		"region": "us-east-1",
		"resources": {
			"nodes": cluster_nodes,
			"pods": cluster_pods,
		},
	}},
}

_node(name, az) := {"metadata": {"name": name, "labels": {"topology.kubernetes.io/zone": az}}}

_node_legacy(name, az) := {"metadata": {"name": name, "labels": {"failure-domain.beta.kubernetes.io/zone": az}}}

_node_no_az(name) := {"metadata": {"name": name, "labels": {}}}

_pod(name, app, node_name) := {
	"metadata": {"name": name, "labels": {"app.kubernetes.io/name": app}},
	"spec": {"nodeName": node_name},
}

# --- App missing from expected AZ ---

test_app_missing_from_az if {
	fixture := _base_fixture(
		[_node("n1", "us-east-1a"), _node("n2", "us-east-1b")],
		[_pod("web-1", "web", "n1"), _pod("web-2", "web", "n2")],
	)

	violations := k8s_az_coverage.violation with input as fixture
	# web is missing from us-east-1c
	count(violations) == 1
	some v, _ in violations
	contains(v.remarks, "us-east-1c")
	contains(v.remarks, "web")
}

# --- App in all expected AZs → no AZ-related violations ---

test_app_covers_all_azs if {
	fixture := _base_fixture(
		[_node("n1", "us-east-1a"), _node("n2", "us-east-1b"), _node("n3", "us-east-1c")],
		[
			_pod("web-1", "web", "n1"),
			_pod("web-2", "web", "n2"),
			_pod("web-3", "web", "n3"),
		],
	)

	violations := k8s_az_coverage.violation with input as fixture
	# no violations (app covers all AZs, expected_azs is set, clusters exist)
	count(violations) == 0
}

# --- Multiple apps, one missing AZ ---

test_multiple_apps_one_missing if {
	fixture := _base_fixture(
		[_node("n1", "us-east-1a"), _node("n2", "us-east-1b"), _node("n3", "us-east-1c")],
		[
			_pod("web-1", "web", "n1"),
			_pod("web-2", "web", "n2"),
			_pod("web-3", "web", "n3"),
			_pod("api-1", "api", "n1"),
			# api only in n1 → missing us-east-1b and us-east-1c
		],
	)

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 2
}

# --- Pod on node with no AZ label ---

test_pod_on_node_without_az_label if {
	fixture := {
		"expected_azs": ["us-east-1a"],
		"clusters": {"prod": {
			"name": "prod",
			"region": "us-east-1",
			"resources": {
				"nodes": [_node("n1", "us-east-1a"), _node_no_az("n2")],
				"pods": [_pod("web-1", "web", "n1"), _pod("web-2", "web", "n2")],
			},
		}},
	}

	violations := k8s_az_coverage.violation with input as fixture
	some v, _ in violations
	contains(v.remarks, "no AZ label")
	contains(v.remarks, "web-2")
}

# --- No expected_azs → violation ---

test_no_expected_azs if {
	fixture := {
		"clusters": {"prod": {
			"name": "prod",
			"region": "us-east-1",
			"resources": {
				"nodes": [_node("n1", "us-east-1a")],
				"pods": [_pod("web-1", "web", "n1")],
			},
		}},
	}

	violations := k8s_az_coverage.violation with input as fixture
	some v, _ in violations
	v.remarks == "No expected_azs configured in policy_input"
}

# --- Empty cluster data → violation ---

test_empty_cluster_data if {
	violations := k8s_az_coverage.violation with input as {}
	some v, _ in violations
	v.remarks == "No cluster data available"
}

# --- Custom app_label ---

test_custom_app_label if {
	fixture := {
		"expected_azs": ["us-east-1a", "us-east-1b"],
		"app_label": "team",
		"clusters": {"prod": {
			"name": "prod",
			"region": "us-east-1",
			"resources": {
				"nodes": [_node("n1", "us-east-1a"), _node("n2", "us-east-1b")],
				"pods": [
					{
						"metadata": {"name": "svc-1", "labels": {"team": "backend"}},
						"spec": {"nodeName": "n1"},
					},
					{
						"metadata": {"name": "svc-2", "labels": {"team": "backend"}},
						"spec": {"nodeName": "n2"},
					},
				],
			},
		}},
	}

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

# --- Legacy label fallback ---

test_legacy_label_fallback if {
	fixture := {
		"expected_azs": ["us-east-1a", "us-east-1b"],
		"clusters": {"prod": {
			"name": "prod",
			"region": "us-east-1",
			"resources": {
				"nodes": [_node_legacy("n1", "us-east-1a"), _node_legacy("n2", "us-east-1b")],
				"pods": [_pod("web-1", "web", "n1"), _pod("web-2", "web", "n2")],
			},
		}},
	}

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

# --- Multi-cluster: web app covers all AZs globally ---

test_multi_cluster_global_coverage if {
	fixture := {
		"expected_azs": ["us-east-1a", "us-east-1b"],
		"clusters": {
			"prod-east": {
				"name": "prod-east",
				"region": "us-east-1",
				"resources": {
					"nodes": [_node("n1", "us-east-1a"), _node("n2", "us-east-1b")],
					"pods": [_pod("web-1", "web", "n1"), _pod("web-2", "web", "n2")],
				},
			},
			"prod-west": {
				"name": "prod-west",
				"region": "us-west-2",
				"resources": {
					"nodes": [_node("n1", "us-east-1a")],
					"pods": [_pod("web-1", "web", "n1")],
				},
			},
		},
	}

	violations := k8s_az_coverage.violation with input as fixture
	# web app covers all AZs globally (us-east-1a and us-east-1b across both clusters)
	count(violations) == 0
}

# --- Multi-cluster: app missing AZ globally ---

test_multi_cluster_global_missing if {
	fixture := {
		"expected_azs": ["us-east-1a", "us-east-1b", "us-east-1c"],
		"clusters": {
			"prod-east": {
				"name": "prod-east",
				"region": "us-east-1",
				"resources": {
					"nodes": [_node("n1", "us-east-1a"), _node("n2", "us-east-1b")],
					"pods": [_pod("web-1", "web", "n1"), _pod("web-2", "web", "n2")],
				},
			},
			"prod-west": {
				"name": "prod-west",
				"region": "us-west-2",
				"resources": {
					"nodes": [_node("n1", "us-east-1a")],
					"pods": [_pod("web-1", "web", "n1")],
				},
			},
		},
	}

	violations := k8s_az_coverage.violation with input as fixture
	# web app missing us-east-1c globally
	count(violations) == 1
	some v, _ in violations
	contains(v.remarks, "default/web")
	contains(v.remarks, "us-east-1c")
}

# --- Pods without app label are ignored ---

test_pods_without_app_label_ignored if {
	fixture := _base_fixture(
		[_node("n1", "us-east-1a"), _node("n2", "us-east-1b"), _node("n3", "us-east-1c")],
		[
			_pod("web-1", "web", "n1"),
			_pod("web-2", "web", "n2"),
			_pod("web-3", "web", "n3"),
			# pod without app label
			{"metadata": {"name": "sidecar", "labels": {}}, "spec": {"nodeName": "n1"}},
		],
	)

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

# --- Title and description ---

test_title if {
	k8s_az_coverage.title == "Kubernetes AZ Coverage Check" with input as {}
}

test_description_with_clusters if {
	fixture := {
		"expected_azs": ["us-east-1a"],
		"clusters": {"prod": {
			"name": "prod",
			"region": "us-east-1",
			"resources": {"nodes": [], "pods": []},
		}},
	}

	d := k8s_az_coverage.description with input as fixture
	contains(d, "1 cluster(s)")
	contains(d, "us-east-1a")
}
