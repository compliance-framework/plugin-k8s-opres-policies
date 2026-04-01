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

_min_az_fixture(min_azs, cluster_nodes, cluster_pods) := {
	"min_azs": min_azs,
	"clusters": {"prod": {
		"name": "prod",
		"region": "us-east-1",
		"resources": {
			"nodes": cluster_nodes,
			"pods": cluster_pods,
		},
	}},
}

_min_region_fixture(min_regions, clusters) := {
	"min_regions": min_regions,
	"clusters": clusters,
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

# --- No compliance criteria → violation ---

test_no_compliance_criteria if {
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
	contains(v.remarks, "No compliance criteria configured")
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
}

# --- min_azs: app meets minimum → no violation ---

test_min_azs_met if {
	fixture := _min_az_fixture(
		2,
		[_node("n1", "us-east-1a"), _node("n2", "us-east-1b")],
		[_pod("web-1", "web", "n1"), _pod("web-2", "web", "n2")],
	)

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

# --- min_azs: app below minimum → violation ---

test_min_azs_not_met if {
	fixture := _min_az_fixture(
		3,
		[_node("n1", "us-east-1a"), _node("n2", "us-east-1b")],
		[_pod("web-1", "web", "n1"), _pod("web-2", "web", "n2")],
	)

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 1
	some v, _ in violations
	contains(v.remarks, "default/web")
	contains(v.remarks, "2 AZ(s)")
	contains(v.remarks, "minimum required is 3")
}

# --- min_azs: counts AZs globally across clusters ---

test_min_azs_global_count if {
	fixture := {
		"min_azs": 3,
		"clusters": {
			"east": {
				"name": "east",
				"region": "us-east-1",
				"resources": {
					"nodes": [_node("n1", "us-east-1a"), _node("n2", "us-east-1b")],
					"pods": [_pod("web-1", "web", "n1"), _pod("web-2", "web", "n2")],
				},
			},
			"west": {
				"name": "west",
				"region": "us-west-2",
				"resources": {
					"nodes": [_node("n3", "us-west-2a")],
					"pods": [_pod("web-3", "web", "n3")],
				},
			},
		},
	}

	violations := k8s_az_coverage.violation with input as fixture
	# web spans us-east-1a, us-east-1b, us-west-2a → 3 AZs → meets min_azs=3
	count(violations) == 0
}

# --- min_regions: app meets minimum → no violation ---

test_min_regions_met if {
	fixture := _min_region_fixture(2, {
		"east": {
			"name": "east",
			"region": "us-east-1",
			"resources": {
				"nodes": [_node("n1", "us-east-1a")],
				"pods": [_pod("web-1", "web", "n1")],
			},
		},
		"west": {
			"name": "west",
			"region": "us-west-2",
			"resources": {
				"nodes": [_node("n2", "us-west-2a")],
				"pods": [_pod("web-2", "web", "n2")],
			},
		},
	})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

# --- min_regions: app below minimum → violation ---

test_min_regions_not_met if {
	fixture := _min_region_fixture(2, {
		"east": {
			"name": "east",
			"region": "us-east-1",
			"resources": {
				"nodes": [_node("n1", "us-east-1a")],
				"pods": [_pod("web-1", "web", "n1")],
			},
		},
	})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 1
	some v, _ in violations
	contains(v.remarks, "default/web")
	contains(v.remarks, "1 region(s)")
	contains(v.remarks, "minimum required is 2")
}

# --- expected_regions: app covers required region → no violation ---

test_expected_regions_met if {
	fixture := {
		"expected_regions": ["us-east-1", "us-west-2"],
		"clusters": {
			"east": {
				"name": "east",
				"region": "us-east-1",
				"resources": {
					"nodes": [_node("n1", "us-east-1a")],
					"pods": [_pod("web-1", "web", "n1")],
				},
			},
			"west": {
				"name": "west",
				"region": "us-west-2",
				"resources": {
					"nodes": [_node("n2", "us-west-2a")],
					"pods": [_pod("web-2", "web", "n2")],
				},
			},
		},
	}

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

# --- expected_regions: app missing required region → violation ---

test_expected_regions_not_met if {
	fixture := {
		"expected_regions": ["us-east-1", "eu-west-1"],
		"clusters": {
			"east": {
				"name": "east",
				"region": "us-east-1",
				"resources": {
					"nodes": [_node("n1", "us-east-1a")],
					"pods": [_pod("web-1", "web", "n1")],
				},
			},
		},
	}

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 1
	some v, _ in violations
	contains(v.remarks, "default/web")
	contains(v.remarks, "eu-west-1")
}

# --- Combined: expected_azs and min_regions, one fails each ---

test_combined_expected_azs_and_min_regions if {
	fixture := {
		"expected_azs": ["us-east-1a", "us-east-1b"],
		"min_regions": 2,
		"clusters": {
			"east": {
				"name": "east",
				"region": "us-east-1",
				"resources": {
					"nodes": [_node("n1", "us-east-1a")],
					"pods": [_pod("web-1", "web", "n1")],
				},
			},
		},
	}

	violations := k8s_az_coverage.violation with input as fixture
	# web missing us-east-1b (expected_azs) AND only 1 region (min_regions=2)
	count(violations) == 2
}

# --- Combined: both min_azs and expected_azs satisfied → no violation ---

test_combined_min_and_explicit_satisfied if {
	fixture := {
		"expected_azs": ["us-east-1a", "us-east-1b"],
		"min_azs": 2,
		"clusters": {
			"east": {
				"name": "east",
				"region": "us-east-1",
				"resources": {
					"nodes": [_node("n1", "us-east-1a"), _node("n2", "us-east-1b")],
					"pods": [_pod("web-1", "web", "n1"), _pod("web-2", "web", "n2")],
				},
			},
		},
	}

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

# --- expected_regions fails while min_azs and min_regions are satisfied ---

test_expected_regions_fails_while_mins_pass if {
	fixture := {
		"min_azs": 2,
		"min_regions": 2,
		"expected_regions": ["eu-central-1"],
		"clusters": {
			"c1": {
				"name": "c1",
				"region": "us-east-1",
				"resources": {
					"nodes": [_node("n1", "us-east-1a")],
					"pods": [_pod("web-1", "web", "n1")],
				},
			},
			"c2": {
				"name": "c2",
				"region": "us-west-2",
				"resources": {
					"nodes": [_node("n2", "us-west-2a"), _node("n3", "us-west-2b")],
					"pods": [_pod("web-2", "web", "n2"), _pod("web-3", "web", "n3")],
				},
			},
		},
	}

	violations := k8s_az_coverage.violation with input as fixture
	# web spans 3 AZs (≥2) and 2 regions (≥2) → min checks pass
	# but eu-central-1 is not covered → expected_regions violation
	count(violations) == 1
	some v, _ in violations
	contains(v.remarks, "default/web")
	contains(v.remarks, "eu-central-1")
}

# --- expected_regions partially fails: one required region missing, mins satisfied ---

test_expected_regions_one_missing_mins_satisfied if {
	fixture := {
		"min_azs": 2,
		"min_regions": 2,
		"expected_regions": ["us-east-1", "ap-southeast-1"],
		"clusters": {
			"c1": {
				"name": "c1",
				"region": "us-east-1",
				"resources": {
					"nodes": [_node("n1", "us-east-1a")],
					"pods": [_pod("web-1", "web", "n1")],
				},
			},
			"c2": {
				"name": "c2",
				"region": "eu-west-1",
				"resources": {
					"nodes": [_node("n2", "eu-west-1a")],
					"pods": [_pod("web-2", "web", "n2")],
				},
			},
		},
	}

	violations := k8s_az_coverage.violation with input as fixture
	# web spans 2 AZs (≥2) and 2 regions (≥2) → min checks pass
	# us-east-1 is covered, but ap-southeast-1 is not → 1 expected_regions violation
	count(violations) == 1
	some v, _ in violations
	contains(v.remarks, "default/web")
	contains(v.remarks, "ap-southeast-1")
}

# --- 3 clusters: 2 same region different AZs, 1 different region → all criteria met ---

test_three_clusters_two_regions_all_criteria_met if {
	fixture := {
		"min_azs": 2,
		"min_regions": 2,
		"expected_regions": ["us-east-1"],
		"clusters": {
			"c1": {
				"name": "c1",
				"region": "us-east-1",
				"resources": {
					"nodes": [_node("n1", "us-east-1a")],
					"pods": [_pod("web-1", "web", "n1")],
				},
			},
			"c2": {
				"name": "c2",
				"region": "us-east-1",
				"resources": {
					"nodes": [_node("n2", "us-east-1b")],
					"pods": [_pod("web-2", "web", "n2")],
				},
			},
			"c3": {
				"name": "c3",
				"region": "eu-west-1",
				"resources": {
					"nodes": [_node("n3", "eu-west-1a")],
					"pods": [_pod("web-3", "web", "n3")],
				},
			},
		},
	}

	violations := k8s_az_coverage.violation with input as fixture
	# web: 3 AZs (≥2), 2 regions (≥2), present in us-east-1 → no violations
	count(violations) == 0
}

# --- 10 clusters, app only in 3 → min checks pass on covered AZs/regions, empty clusters are invisible ---

test_ten_clusters_app_in_three_passes_min_checks if {
	fixture := {
		"min_azs": 2,
		"min_regions": 2,
		"expected_regions": ["us-east-1"],
		"clusters": {
			"c1":  {"name": "c1",  "region": "us-east-1",      "resources": {"nodes": [_node("n1",  "us-east-1a")],      "pods": [_pod("web-1", "web", "n1")]}},
			"c2":  {"name": "c2",  "region": "us-east-1",      "resources": {"nodes": [_node("n2",  "us-east-1b")],      "pods": [_pod("web-2", "web", "n2")]}},
			"c3":  {"name": "c3",  "region": "eu-west-1",      "resources": {"nodes": [_node("n3",  "eu-west-1a")],      "pods": [_pod("web-3", "web", "n3")]}},
			"c4":  {"name": "c4",  "region": "ap-southeast-1", "resources": {"nodes": [_node("n4",  "ap-southeast-1a")], "pods": []}},
			"c5":  {"name": "c5",  "region": "ap-southeast-1", "resources": {"nodes": [_node("n5",  "ap-southeast-1b")], "pods": []}},
			"c6":  {"name": "c6",  "region": "us-west-2",      "resources": {"nodes": [_node("n6",  "us-west-2a")],      "pods": []}},
			"c7":  {"name": "c7",  "region": "us-west-2",      "resources": {"nodes": [_node("n7",  "us-west-2b")],      "pods": []}},
			"c8":  {"name": "c8",  "region": "eu-central-1",   "resources": {"nodes": [_node("n8",  "eu-central-1a")],   "pods": []}},
			"c9":  {"name": "c9",  "region": "eu-central-1",   "resources": {"nodes": [_node("n9",  "eu-central-1b")],   "pods": []}},
			"c10": {"name": "c10", "region": "sa-east-1",      "resources": {"nodes": [_node("n10", "sa-east-1a")],      "pods": []}},
		},
	}

	violations := k8s_az_coverage.violation with input as fixture
	# web spans 3 AZs and 2 regions across the 3 clusters it's deployed in.
	# The 7 empty clusters are not visible to the policy — min checks pass.
	count(violations) == 0
}
