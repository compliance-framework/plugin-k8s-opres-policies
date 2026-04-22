package compliance_framework.k8s_az_coverage_test

import data.compliance_framework.k8s_az_coverage
import rego.v1

_node(name, az) := {"metadata": {"name": name, "labels": {"topology.kubernetes.io/zone": az}}}

_node_legacy(name, az) := {"metadata": {"name": name, "labels": {"failure-domain.beta.kubernetes.io/zone": az}}}

_node_with_region(name, az, region) := {"metadata": {"name": name, "labels": {"topology.kubernetes.io/zone": az, "topology.kubernetes.io/region": region}}}

_node_no_az(name) := {"metadata": {"name": name, "labels": {}}}

_pod(name, namespace, app, node_name) := {
	"metadata": {"name": name, "namespace": namespace, "labels": {"app.kubernetes.io/name": app}},
	"spec": {"nodeName": node_name},
}

_pod_with_label(name, namespace, label_key, label_value, node_name) := {
	"metadata": {"name": name, "namespace": namespace, "labels": {label_key: label_value}},
	"spec": {"nodeName": node_name},
}

_deployment(name, namespace, app) := {
	"metadata": {
		"name": name,
		"namespace": namespace,
		"labels": {"app.kubernetes.io/name": app},
	},
	"spec": {
		"template": {
			"metadata": {
				"labels": {"app.kubernetes.io/name": app},
			},
		},
	},
}

_deployment_with_selector(name, namespace, selector_labels) := {
	"metadata": {
		"name": name,
		"namespace": namespace,
	},
	"spec": {
		"selector": {
			"matchLabels": selector_labels,
		},
		"template": {
			"metadata": {
				"labels": selector_labels,
			},
		},
	},
}

_deployment_with_match_expressions(name, namespace, match_expressions, template_labels) := {
	"metadata": {
		"name": name,
		"namespace": namespace,
	},
	"spec": {
		"selector": {
			"matchExpressions": match_expressions,
		},
		"template": {
			"metadata": {
				"labels": template_labels,
			},
		},
	},
}

_deployment_template_only(name, namespace, app) := {
	"metadata": {
		"name": name,
		"namespace": namespace,
	},
	"spec": {
		"template": {
			"metadata": {
				"labels": {"app.kubernetes.io/name": app},
			},
		},
	},
}

_deployment_with_label(name, namespace, label_key, label_value) := {
	"metadata": {
		"name": name,
		"namespace": namespace,
		"labels": {label_key: label_value},
	},
	"spec": {
		"template": {
			"metadata": {
				"labels": {label_key: label_value},
			},
		},
	},
}

_cluster(name, region, nodes, pods, deployments) := {
	"cluster": {
		"name": name,
		"region": region,
		"provider": "eks",
	},
	"resources": {
		"nodes": nodes,
		"pods": pods,
		"deployments": deployments,
	},
}

_subject(cluster_name, namespace, name, app_name) := {
	"cluster_name": cluster_name,
	"resource_type": "deployments",
	"namespace": namespace,
	"name": name,
	"identifier": sprintf("k8s-deployments/%s/%s/%s", [cluster_name, namespace, name]),
	"identity_labels": {
		"app_name": app_name,
	},
}

_input(main, subject, clusters, extra) := object.union({
	"schema_version": "v2",
	"source": "plugin-kubernetes",
	"main": main,
	"subject": subject,
	"context": object.get(clusters, object.get(subject, "cluster_name", ""), {"cluster": {}, "resources": {}}),
	"fleet": {"clusters": clusters},
}, extra)

test_app_missing_from_expected_az_if_deployment_subject if {
	main := _deployment("web", "app", "web")
	clusters := {
		"prod": _cluster("prod", "us-east-1",
			[_node("n1", "us-east-1a"), _node("n2", "us-east-1b")],
			[_pod("web-1", "app", "web", "n1"), _pod("web-2", "app", "web", "n2")],
			[main],
		),
	}
	fixture := _input(main, _subject("prod", "app", "web", "web"), clusters, {"expected_azs": ["us-east-1a", "us-east-1b", "us-east-1c"]})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 1
	some v, _ in violations
	contains(v.remarks, "app/web")
	contains(v.remarks, "us-east-1c")
}

test_app_covers_all_expected_azs_if_deployment_subject if {
	main := _deployment("web", "app", "web")
	clusters := {
		"prod": _cluster("prod", "us-east-1",
			[_node("n1", "us-east-1a"), _node("n2", "us-east-1b"), _node("n3", "us-east-1c")],
			[_pod("web-1", "app", "web", "n1"), _pod("web-2", "app", "web", "n2"), _pod("web-3", "app", "web", "n3")],
			[main],
		),
	}
	fixture := _input(main, _subject("prod", "app", "web", "web"), clusters, {"expected_azs": ["us-east-1a", "us-east-1b", "us-east-1c"]})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

test_many_pods_same_namespace_are_evaluated_as_one_app if {
	main := _deployment("web", "app", "web")
	clusters := {
		"prod": _cluster("prod", "us-east-1",
			[_node("n1", "us-east-1a"), _node("n2", "us-east-1b"), _node("n3", "us-east-1c")],
			[
				_pod("web-1", "app", "web", "n1"),
				_pod("web-2", "app", "web", "n1"),
				_pod("web-3", "app", "web", "n1"),
				_pod("web-4", "app", "web", "n2"),
				_pod("web-5", "app", "web", "n2"),
				_pod("web-6", "app", "web", "n2"),
				_pod("web-7", "app", "web", "n3"),
				_pod("web-8", "app", "web", "n3"),
				_pod("web-9", "app", "web", "n3"),
				_pod("web-10", "app", "web", "n3"),
			],
			[main],
		),
	}
	fixture := _input(main, _subject("prod", "app", "web", "web"), clusters, {"min_azs": 3})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

test_current_deployment_ignores_other_apps if {
	main := _deployment("web", "app", "web")
	clusters := {
		"prod": _cluster("prod", "us-east-1",
			[_node("n1", "us-east-1a"), _node("n2", "us-east-1b")],
			[
				_pod("web-1", "app", "web", "n1"),
				_pod("web-2", "app", "web", "n2"),
				_pod("api-1", "app", "api", "n1"),
			],
			[main, _deployment("api", "app", "api")],
		),
	}
	fixture := _input(main, _subject("prod", "app", "web", "web"), clusters, {"expected_azs": ["us-east-1a", "us-east-1b"]})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

test_deployment_selector_matches_pods_without_app_name_label if {
	main := _deployment_with_selector("coredns", "kube-system", {"k8s-app": "kube-dns"})
	clusters := {
		"kind": _cluster("kind", "local",
			[_node("kind-control-plane", "us-west-1a")],
			[
				{
					"metadata": {"name": "coredns-1", "namespace": "kube-system", "labels": {"k8s-app": "kube-dns"}},
					"spec": {"nodeName": "kind-control-plane"},
				},
			],
			[main],
		),
	}
	fixture := _input(main, _subject("kind", "kube-system", "coredns", "coredns"), clusters, {"min_azs": 1})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

test_deployment_selector_match_expressions_match_pods if {
	main := _deployment_with_match_expressions(
		"api",
		"app",
		[{"key": "tier", "operator": "In", "values": ["frontend"]}],
		{"tier": "frontend"},
	)
	clusters := {
		"prod": _cluster("prod", "us-east-1",
			[_node("n1", "us-east-1a")],
			[
				{
					"metadata": {"name": "api-1", "namespace": "app", "labels": {"tier": "frontend"}},
					"spec": {"nodeName": "n1"},
				},
			],
			[main],
		),
	}
	fixture := _input(main, _subject("prod", "app", "api", "api"), clusters, {"min_azs": 1})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

test_selector_workloads_do_not_fall_back_to_app_label_matching if {
	main := _deployment_with_selector("web", "app", {"component": "web"})
	clusters := {
		"prod": _cluster("prod", "us-east-1",
			[_node("n1", "us-east-1a"), _node("n2", "us-east-1b")],
			[
				{
					"metadata": {"name": "web-selected", "namespace": "app", "labels": {"component": "web", "app.kubernetes.io/name": "web"}},
					"spec": {"nodeName": "n1"},
				},
				{
					"metadata": {"name": "web-unrelated", "namespace": "app", "labels": {"component": "other", "app.kubernetes.io/name": "web"}},
					"spec": {"nodeName": "n2"},
				},
			],
			[main],
		),
	}
	fixture := _input(main, _subject("prod", "app", "web", "web"), clusters, {"expected_azs": ["us-east-1a", "us-east-1b"]})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 1
	some v, _ in violations
	contains(v.remarks, "required AZ us-east-1b")
}

test_pod_on_node_without_az_label if {
	main := _deployment("web", "app", "web")
	clusters := {
		"prod": _cluster("prod", "us-east-1",
			[_node("n1", "us-east-1a"), _node_no_az("n2")],
			[_pod("web-1", "app", "web", "n1"), _pod("web-2", "app", "web", "n2")],
			[main],
		),
	}
	fixture := _input(main, _subject("prod", "app", "web", "web"), clusters, {"expected_azs": ["us-east-1a"]})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 1
	some v, _ in violations
	contains(v.remarks, "no AZ label")
	contains(v.remarks, "web-2")
}

test_custom_app_label if {
	main := _deployment_with_label("backend", "app", "team", "backend")
	clusters := {
		"prod": _cluster("prod", "us-east-1",
			[_node("n1", "us-east-1a"), _node("n2", "us-east-1b")],
			[_pod_with_label("svc-1", "app", "team", "backend", "n1"), _pod_with_label("svc-2", "app", "team", "backend", "n2")],
			[main],
		),
	}
	fixture := _input(main, _subject("prod", "app", "backend", "backend"), clusters, {"app_label": "team", "expected_azs": ["us-east-1a", "us-east-1b"]})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

test_legacy_label_fallback if {
	main := _deployment("web", "app", "web")
	clusters := {
		"prod": _cluster("prod", "us-east-1",
			[_node_legacy("n1", "us-east-1a"), _node_legacy("n2", "us-east-1b")],
			[_pod("web-1", "app", "web", "n1"), _pod("web-2", "app", "web", "n2")],
			[main],
		),
	}
	fixture := _input(main, _subject("prod", "app", "web", "web"), clusters, {"expected_azs": ["us-east-1a", "us-east-1b"]})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

test_multi_cluster_global_coverage if {
	main := _deployment("web", "app", "web")
	clusters := {
		"prod-east": _cluster("prod-east", "us-east-1",
			[_node("n1", "us-east-1a")],
			[_pod("web-1", "app", "web", "n1")],
			[main],
		),
		"prod-west": _cluster("prod-west", "us-west-2",
			[_node("n2", "us-east-1b")],
			[_pod("web-2", "app", "web", "n2")],
			[_deployment("web", "app", "web")],
		),
	}
	fixture := _input(main, _subject("prod-east", "app", "web", "web"), clusters, {"expected_azs": ["us-east-1a", "us-east-1b"]})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

test_min_regions_and_expected_regions_use_cross_cluster_coverage if {
	main := _deployment("web", "app", "web")
	clusters := {
		"east": _cluster("east", "us-east-1",
			[_node("n1", "us-east-1a")],
			[_pod("web-1", "app", "web", "n1")],
			[main],
		),
		"west": _cluster("west", "us-west-2",
			[_node("n2", "us-west-2a")],
			[_pod("web-2", "app", "web", "n2")],
			[_deployment("web", "app", "web")],
		),
	}
	fixture := _input(main, _subject("east", "app", "web", "web"), clusters, {"min_regions": 2, "expected_regions": ["us-east-1", "us-west-2"]})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

test_expected_regions_not_met if {
	main := _deployment("web", "app", "web")
	clusters := {
		"east": _cluster("east", "us-east-1",
			[_node("n1", "us-east-1a")],
			[_pod("web-1", "app", "web", "n1")],
			[main],
		),
	}
	fixture := _input(main, _subject("east", "app", "web", "web"), clusters, {"expected_regions": ["us-east-1", "eu-west-1"]})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 1
	some v, _ in violations
	contains(v.remarks, "app/web")
	contains(v.remarks, "eu-west-1")
}

test_min_regions_falls_back_to_node_region_labels if {
	main := _deployment("web", "app", "web")
	clusters := {
		"east": _cluster("east", "",
			[_node_with_region("n1", "us-east-1a", "us-east-1")],
			[_pod("web-1", "app", "web", "n1")],
			[main],
		),
		"west": _cluster("west", "",
			[_node_with_region("n2", "us-west-2a", "us-west-2")],
			[_pod("web-2", "app", "web", "n2")],
			[_deployment("web", "app", "web")],
		),
	}
	fixture := _input(main, _subject("east", "app", "web", "web"), clusters, {"min_regions": 2})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

test_conflicting_node_region_labels_do_not_satisfy_min_regions if {
	main := _deployment("web", "app", "web")
	clusters := {
		"mixed": _cluster("mixed", "",
			[
				_node_with_region("n1", "us-east-1a", "us-east-1"),
				_node_with_region("n2", "us-east-1b", "us-west-2"),
			],
			[
				_pod("web-1", "app", "web", "n1"),
				_pod("web-2", "app", "web", "n2"),
			],
			[main],
		),
	}
	fixture := _input(main, _subject("mixed", "app", "web", "web"), clusters, {"min_regions": 1})

	raw_violations := k8s_az_coverage.violation with input as fixture
	violations := [v.remarks |
		some v, _ in raw_violations
	]
	count(violations) == 1
	some v in violations
	contains(v, "spans only 0 region(s)")
	contains(v, "current regions: none observed")
}

test_failure_messages_include_observed_az_and_region_counts if {
	main := _deployment("web", "app", "web")
	clusters := {
		"kind-a": _cluster("kind-a", "local",
			[_node("n1", "local-a")],
			[_pod("web-1", "app", "web", "n1"), _pod("web-2", "app", "web", "n1")],
			[main],
		),
		"kind-b": _cluster("kind-b", "local",
			[_node("n2", "local-b")],
			[_pod("web-3", "app", "web", "n2")],
			[_deployment("web", "app", "web")],
		),
	}
	fixture := _input(main, _subject("kind-a", "app", "web", "web"), clusters, {"min_azs": 3, "min_regions": 2})
 
	raw_violations := k8s_az_coverage.violation with input as fixture
	violations := [v.remarks |
		some v, _ in raw_violations
	]
 	description := k8s_az_coverage.description with input as fixture
 
 	count(violations) == 2
 	some v in violations
 	contains(v, "current AZs: local-a - seen twice, local-b - seen once")
 	some region_violation in violations
 	contains(region_violation, "current regions: local - seen in 2 clusters")
 	contains(description, "only 2/3 AZs (current AZs: local-a - seen twice, local-b - seen once)")
 	contains(description, "only 1/2 regions (current regions: local - seen in 2 clusters)")
 }

 test_subject_identity_label_fallback_if_main_is_missing_metadata_label if {
 	main := {"metadata": {"name": "web", "namespace": "app"}}
	clusters := {
		"prod": _cluster("prod", "us-east-1",
			[_node("n1", "us-east-1a"), _node("n2", "us-east-1b")],
			[_pod("web-1", "app", "web", "n1"), _pod("web-2", "app", "web", "n2")],
			[main],
		),
	}
	fixture := _input(main, _subject("prod", "app", "web", "web"), clusters, {"expected_azs": ["us-east-1a", "us-east-1b"]})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

test_main_deployment_template_label_is_used if {
	main := _deployment_template_only("web", "app", "web")
	clusters := {
		"prod": _cluster("prod", "us-east-1",
			[_node("n1", "us-east-1a"), _node("n2", "us-east-1b")],
			[_pod("web-1", "app", "web", "n1"), _pod("web-2", "app", "web", "n2")],
			[main],
		),
	}
	fixture := _input(main, _subject("prod", "app", "web", "web"), clusters, {"expected_azs": ["us-east-1a", "us-east-1b"]})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 0
}

test_no_compliance_criteria if {
	main := _deployment("web", "app", "web")
	clusters := {
		"prod": _cluster("prod", "us-east-1", [_node("n1", "us-east-1a")], [_pod("web-1", "app", "web", "n1")], [main]),
	}
	fixture := _input(main, _subject("prod", "app", "web", "web"), clusters, {})

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 1
	some v, _ in violations
	contains(v.remarks, "No compliance criteria configured")
}

test_empty_cluster_data if {
	fixture := {
		"main": _deployment("web", "app", "web"),
		"subject": _subject("prod", "app", "web", "web"),
		"fleet": {"clusters": {}},
	}

	violations := k8s_az_coverage.violation with input as fixture
	count(violations) == 1
	some v, _ in violations
	v.remarks == "No cluster data available"
}

test_title if {
	fixture := _input(_deployment("web", "app", "web"), _subject("prod", "app", "web", "web"), {}, {})
	k8s_az_coverage.title == "AZ checks for k8s deployment prod/app/web" with input as fixture
}

test_risk_templates if {
	fixture := _input(_deployment("web", "app", "web"), _subject("prod", "app", "web", "web"), {}, {})
	risk_templates := k8s_az_coverage.risk_templates with input as fixture
	count(risk_templates) == 1
	risk_templates[0].name == "Application may be non-resilient due to insufficient multi-AZ or multi-region coverage"
	risk_templates[0].title == "Application {{ .namespace }}/{{ .app_name }} may be non-resilient due to insufficient multi-AZ or multi-region coverage"
	risk_templates[0].statement == "Application {{ .namespace }}/{{ .app_name }} is not distributed across the required availability zones or regions and may be unable to tolerate node, zone, or regional failures. Concentrating replicas in too few failure domains increases the likelihood of service disruption, degraded availability, and delayed recovery during infrastructure incidents or maintenance events."
	risk_templates[0].likelihood_hint == "moderate"
	risk_templates[0].impact_hint == "high"
	risk_templates[0].dedupe_label_keys == ["namespace", "app_name"]
	count(risk_templates[0].label_schema) == 2
	risk_templates[0].label_schema[0].key == "namespace"
	risk_templates[0].label_schema[1].key == "app_name"
	risk_templates[0].remediation.title == "Distribute application replicas across independent failure domains"
	count(risk_templates[0].remediation.tasks) == 5
}

test_description_with_clusters if {
	main := _deployment("web", "app", "web")
	clusters := {
		"prod": _cluster("prod", "us-east-1", [], [], [main]),
	}
	fixture := _input(main, _subject("prod", "app", "web", "web"), clusters, {"expected_azs": ["us-east-1a"]})

	d := k8s_az_coverage.description with input as fixture
	contains(d, "1 cluster(s)")
}
