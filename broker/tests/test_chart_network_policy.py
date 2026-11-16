"""The chart derives the broker's egress NetworkPolicy rules from configured URLs.

Each test renders the chart live with ``helm`` (a dev-environment dependency)
over ``ci/test-values.yaml`` plus an overlay and asserts on the broker's
rendered NetworkPolicy. An in-cluster URL becomes a namespace selector paired
with the pod selector declared under ``networkPolicy.endpoints``, on the URL's
port or the endpoint's pod port; every other host shares the dual-stack
public-internet rule, which ``networkPolicy.external`` and
``networkPolicy.extraEgress`` can narrow or extend.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CHART = _REPO_ROOT / "charts" / "af-mcp-platform"
_BASE_VALUES = _CHART / "ci" / "test-values.yaml"
_NAMESPACE_LABEL = "kubernetes.io/metadata.name"
_RELEASE_NAMESPACE = "mcp-test"
_SELECTOR = {"app.kubernetes.io/name": "svc"}


def _helm_template(
    tmp_path: Path, overlay: dict[str, Any]
) -> subprocess.CompletedProcess[str]:
    """Render the chart over the CI base values plus *overlay*; never raises on failure."""
    overlay_file = tmp_path / "overlay.yaml"
    overlay_file.write_text(yaml.safe_dump(overlay))
    return subprocess.run(
        [
            "helm",
            "template",
            "af-mcp-platform",
            str(_CHART),
            "--namespace",
            _RELEASE_NAMESPACE,
            "--set",
            "image.broker.tag=sha-test",
            "--set",
            "image.portal.tag=sha-test",
            "-f",
            str(_BASE_VALUES),
            "-f",
            str(overlay_file),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def _policies(tmp_path: Path, overlay: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Render and return the chart's NetworkPolicies keyed by name."""
    result = _helm_template(tmp_path, overlay)
    assert result.returncode == 0, result.stderr
    docs = [d for d in yaml.safe_load_all(result.stdout) if d]
    return {d["metadata"]["name"]: d for d in docs if d["kind"] == "NetworkPolicy"}


def _broker_egress(
    tmp_path: Path, overlay: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    return _policies(tmp_path, overlay or {})["af-mcp-platform-broker"]["spec"][
        "egress"
    ]


def _namespace_rules(egress: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Egress rules that select a namespace, keyed by that namespace's name.

    A rule with a pod selector is keyed ``<namespace>/<pod label values>``.
    """
    rules: dict[str, dict[str, Any]] = {}
    for rule in egress:
        for peer in rule.get("to", []):
            if "namespaceSelector" not in peer:
                continue
            key = peer["namespaceSelector"]["matchLabels"][_NAMESPACE_LABEL]
            pod_labels = peer.get("podSelector", {}).get("matchLabels")
            if pod_labels:
                key += "/" + ",".join(f"{k}={v}" for k, v in sorted(pod_labels.items()))
            rules[key] = rule
    return rules


def _ports(rule: dict[str, Any]) -> list[int]:
    return sorted(p["port"] for p in rule["ports"])


def _public_rule(egress: list[dict[str, Any]]) -> dict[str, Any]:
    [rule] = [
        r
        for r in egress
        if any(p.get("ipBlock", {}).get("cidr") == "0.0.0.0/0" for p in r.get("to", []))
    ]
    return rule


def _blocks(rule: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The rule's ipBlocks keyed by cidr."""
    return {p["ipBlock"]["cidr"]: p["ipBlock"] for p in rule["to"]}


def _endpoints(*hosts: str, **options: Any) -> dict[str, Any]:
    """``networkPolicy.egress`` selecting the pods behind each of *hosts*."""
    return {
        "egress": {
            "endpoints": {h: {"podSelector": _SELECTOR, **options} for h in hosts}
        }
    }


def _service(url: str, name: str = "extra") -> dict[str, Any]:
    return {
        "name": name,
        "prefix": name,
        "url": url,
        "transport": "http",
        "required_permission": "__none__",
    }


class TestServiceUrls:
    def test_service_in_another_namespace_pairs_its_namespace_with_its_pods(
        self, tmp_path: Path
    ) -> None:
        host = "svc.backend.svc.cluster.local"
        overlay = {
            "aggregator": {"services": [_service(f"http://{host}:9000/mcp")]},
            "networkPolicy": _endpoints(host),
        }

        rules = _namespace_rules(_broker_egress(tmp_path, overlay))

        assert _ports(rules["backend/app.kubernetes.io/name=svc"]) == [9000]
        assert "backend" not in rules

    def test_missing_port_defaults_from_the_scheme(self, tmp_path: Path) -> None:
        overlay = {
            "aggregator": {
                "services": [
                    _service("http://web.plain.svc.cluster.local/mcp", "plain"),
                    _service("https://web.secure.svc.cluster.local/mcp", "secure"),
                ]
            },
            "networkPolicy": _endpoints(
                "web.plain.svc.cluster.local", "web.secure.svc.cluster.local"
            ),
        }

        rules = _namespace_rules(_broker_egress(tmp_path, overlay))

        assert _ports(rules["plain/app.kubernetes.io/name=svc"]) == [80]
        assert _ports(rules["secure/app.kubernetes.io/name=svc"]) == [443]

    def test_single_label_host_is_in_the_release_namespace(
        self, tmp_path: Path
    ) -> None:
        overlay = {
            "aggregator": {"services": [_service("http://svc:8080/mcp")]},
            "networkPolicy": _endpoints("svc"),
        }

        rules = _namespace_rules(_broker_egress(tmp_path, overlay))

        assert _ports(rules[f"{_RELEASE_NAMESPACE}/app.kubernetes.io/name=svc"]) == [
            8080
        ]

    def test_services_sharing_a_host_yield_one_rule_with_each_port_once(
        self, tmp_path: Path
    ) -> None:
        overlay = {
            "aggregator": {
                "services": [
                    _service("http://svc.backend.svc:8080/a", "a"),
                    _service("http://svc.backend.svc:8080/b", "b"),
                    _service("http://svc.backend.svc:9000/c", "c"),
                ]
            },
            "networkPolicy": _endpoints("svc.backend.svc"),
        }

        egress = _broker_egress(tmp_path, overlay)

        backend = [
            r
            for r in egress
            for p in r.get("to", [])
            if p.get("namespaceSelector", {})
            .get("matchLabels", {})
            .get(_NAMESPACE_LABEL)
            == "backend"
        ]
        assert len(backend) == 1
        assert _ports(backend[0]) == [8080, 9000]

    def test_target_port_replaces_the_service_port(self, tmp_path: Path) -> None:
        # A Service port (80) is not the pod port a NetworkPolicy matches.
        host = "svc.backend.svc.cluster.local"
        overlay = {
            "aggregator": {"services": [_service(f"http://{host}:80/mcp")]},
            "networkPolicy": _endpoints(host, targetPort=9000),
        }

        rules = _namespace_rules(_broker_egress(tmp_path, overlay))

        assert _ports(rules["backend/app.kubernetes.io/name=svc"]) == [9000]

    def test_in_cluster_host_without_a_pod_selector_is_refused(
        self, tmp_path: Path
    ) -> None:
        overlay = {
            "aggregator": {"services": [_service("http://svc.backend.svc:8080/mcp")]},
            "networkPolicy": {"egress": {"endpoints": {}}},
        }

        result = _helm_template(tmp_path, overlay)

        assert result.returncode != 0
        assert "svc.backend.svc" in result.stderr
        assert "podSelector" in result.stderr

    def test_empty_pod_selector_opts_into_the_whole_namespace(
        self, tmp_path: Path
    ) -> None:
        host = "svc.backend.svc"
        overlay = {
            "aggregator": {"services": [_service(f"http://{host}:8080/mcp")]},
            "networkPolicy": {"egress": {"endpoints": {host: {"podSelector": {}}}}},
        }

        rules = _namespace_rules(_broker_egress(tmp_path, overlay))

        assert _ports(rules["backend"]) == [8080]


class TestHairpinnedHosts:
    def test_public_host_served_in_cluster_is_routed_to_the_serving_pods(
        self, tmp_path: Path
    ) -> None:
        # The LB IP behind a public hostname is DNATed to private pod IPs
        # before policy runs, so the public rule never matches it.
        host = "hub.example.org"
        overlay = {
            "aggregator": {"services": [_service(f"https://{host}/mcp")]},
            "networkPolicy": {
                "egress": {
                    "endpoints": {
                        host: {
                            "namespace": "gateway",
                            "podSelector": {"gateway/owner": "public"},
                            "targetPort": 10443,
                        }
                    }
                }
            },
        }

        egress = _broker_egress(tmp_path, overlay)

        rules = _namespace_rules(egress)
        assert _ports(rules["gateway/gateway/owner=public"]) == [10443]
        assert _ports(_public_rule(egress)) == [443]

    def test_public_host_without_a_namespace_stays_external(
        self, tmp_path: Path
    ) -> None:
        host = "hub.example.org"
        overlay = {
            "aggregator": {"services": [_service(f"https://{host}:8443/mcp")]},
            "networkPolicy": {
                "egress": {"endpoints": {host: {"podSelector": _SELECTOR}}}
            },
        }

        egress = _broker_egress(tmp_path, overlay)

        assert _ports(_public_rule(egress)) == [443, 8443]
        assert "hub.example.org" not in str(_namespace_rules(egress))


class TestOtherUrlSources:
    def test_oidc_internal_url_vault_addr_and_identity_provider_urls(
        self, tmp_path: Path
    ) -> None:
        hosts = {
            "kc.keycloak.svc.cluster.local": "keycloak",
            "bao.openbao.svc.cluster.local": "openbao",
            "condor.htcondor.svc": "htcondor",
            "token.tokens.svc.cluster.local": "tokens",
        }
        overlay = {
            "broker": {
                "oidc": {
                    "internalUrl": "http://kc.keycloak.svc.cluster.local:8080/realms/r"
                },
                "oauth21": {
                    "tokenStore": {
                        "backend": "vault",
                        "vault": {"addr": "http://bao.openbao.svc.cluster.local:8200"},
                    }
                },
                "credmon": {"htcondorApiUrl": "http://condor.htcondor.svc:8080"},
                "identityProviders": [
                    {
                        "type": "condor-token",
                        "alias": "condor",
                        "displayName": "HTCondor",
                        "enables": "HTCondor",
                        "targets": [],
                        "serviceUrl": "http://token.tokens.svc.cluster.local:8081",
                    }
                ],
            },
            "networkPolicy": _endpoints(*hosts),
        }

        rules = _namespace_rules(_broker_egress(tmp_path, overlay))

        selector = "app.kubernetes.io/name=svc"
        assert _ports(rules[f"keycloak/{selector}"]) == [8080]
        assert _ports(rules[f"openbao/{selector}"]) == [8200]
        assert _ports(rules[f"htcondor/{selector}"]) == [8080]
        assert _ports(rules[f"tokens/{selector}"]) == [8081]

    def test_issuer_is_not_connected_to_while_an_internal_url_is_set(
        self, tmp_path: Path
    ) -> None:
        # The broker reaches Keycloak through internalUrl, so an in-cluster
        # issuer host must not demand a pod selector of its own.
        overlay = {
            "oidc": {"issuer": "http://issuer.idp.svc/realms/r"},
            "broker": {"oidc": {"internalUrl": "http://kc.keycloak.svc:8080/realms/r"}},
            "networkPolicy": _endpoints("kc.keycloak.svc"),
        }

        rules = _namespace_rules(_broker_egress(tmp_path, overlay))

        assert not any(key.startswith("idp") for key in rules)

    def test_browser_followed_endpoints_get_no_rule(self, tmp_path: Path) -> None:
        overlay = {
            "broker": {
                "identityProviders": [
                    {
                        "type": "oauth21-direct",
                        "alias": "hub",
                        "displayName": "Hub",
                        "enables": "Hub",
                        "targets": [],
                        "authorizationEndpoint": "http://hub.browser.svc:8000/authorize",
                        "tokenEndpoint": "http://hub.tokenns.svc:8000/token",
                        "issuer": "http://hub.issuerns.svc:8000",
                    }
                ]
            },
            "networkPolicy": _endpoints("hub.tokenns.svc"),
        }

        rules = _namespace_rules(_broker_egress(tmp_path, overlay))

        assert any(key.startswith("tokenns/") for key in rules)
        assert not any(key.startswith(("browser", "issuerns")) for key in rules)

    def test_otlp_endpoint_is_allowed_only_while_a_signal_is_enabled(
        self, tmp_path: Path
    ) -> None:
        otlp = {"endpoint": "http://collector.observability.svc:4318"}
        policy = _endpoints("collector.observability.svc")

        off = _namespace_rules(
            _broker_egress(
                tmp_path, {"broker": {"otlp": otlp}, "networkPolicy": policy}
            )
        )
        on = _namespace_rules(
            _broker_egress(
                tmp_path,
                {
                    "broker": {"otlp": otlp, "tracing": {"enabled": True}},
                    "networkPolicy": policy,
                },
            )
        )

        assert not any(key.startswith("observability") for key in off)
        assert _ports(on["observability/app.kubernetes.io/name=svc"]) == [4318]


class TestExternalUrls:
    def test_external_hosts_share_the_public_rule_and_get_no_namespace_rule(
        self, tmp_path: Path
    ) -> None:
        egress = _broker_egress(tmp_path)

        assert _ports(_public_rule(egress)) == [443]
        assert "example.com" not in " ".join(_namespace_rules(egress))

    def test_external_url_on_another_port_widens_only_the_public_rule_ports(
        self, tmp_path: Path
    ) -> None:
        overlay = {
            "aggregator": {"services": [_service("https://api.example.org:8443/mcp")]}
        }

        egress = _broker_egress(tmp_path, overlay)

        assert _ports(_public_rule(egress)) == [443, 8443]
        assert "api.example.org" not in str(_namespace_rules(egress))

    def test_public_rule_has_an_ipv6_twin(self, tmp_path: Path) -> None:
        # Pods are dual-stack: without the ::/0 block, IPv6 egress is dropped
        # and clients that try IPv6 first stall until they fall back.
        blocks = _blocks(_public_rule(_broker_egress(tmp_path)))

        assert set(blocks) == {"0.0.0.0/0", "::/0"}

    def test_public_rule_excludes_private_link_local_and_metadata_addresses(
        self, tmp_path: Path
    ) -> None:
        blocks = _blocks(_public_rule(_broker_egress(tmp_path)))

        assert blocks["0.0.0.0/0"]["except"] == [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.169.254/32",
        ]
        assert blocks["::/0"]["except"] == ["fc00::/7", "fe80::/10"]

    def test_external_except_cidrs_are_split_by_address_family(
        self, tmp_path: Path
    ) -> None:
        overlay = {
            "networkPolicy": {
                "egress": {
                    "external": {"exceptCidrs": ["192.0.2.0/23", "2001:db8:1::/64"]}
                }
            }
        }

        blocks = _blocks(_public_rule(_broker_egress(tmp_path, overlay)))

        assert blocks["0.0.0.0/0"]["except"][-1] == "192.0.2.0/23"
        assert "2001:db8:1::/64" not in blocks["0.0.0.0/0"]["except"]
        assert blocks["::/0"]["except"][-1] == "2001:db8:1::/64"
        assert "192.0.2.0/23" not in blocks["::/0"]["except"]


class TestEscapeHatchAndSwitches:
    def test_extra_egress_rules_are_appended_verbatim(self, tmp_path: Path) -> None:
        extra = {
            "to": [{"ipBlock": {"cidr": "203.0.113.0/24"}}],
            "ports": [{"protocol": "TCP", "port": 6443}],
        }

        egress = _broker_egress(
            tmp_path, {"networkPolicy": {"egress": {"extraEgress": [extra]}}}
        )

        assert egress[-1] == extra

    def test_disabled_policy_renders_no_network_policies(self, tmp_path: Path) -> None:
        assert _policies(tmp_path, {"networkPolicy": {"enabled": False}}) == {}

    def test_dns_rule_is_always_present(self, tmp_path: Path) -> None:
        egress = _broker_egress(tmp_path)

        assert egress[0]["ports"] == [
            {"protocol": "UDP", "port": 53},
            {"protocol": "TCP", "port": 53},
        ]

    def test_url_with_an_unknown_scheme_and_no_port_is_refused(
        self, tmp_path: Path
    ) -> None:
        overlay = {"aggregator": {"services": [_service("grpc://svc.backend.svc/x")]}}

        result = _helm_template(tmp_path, overlay)

        assert result.returncode != 0
        assert "grpc://svc.backend.svc/x" in result.stderr

    def test_removed_service_ports_key_is_rejected_by_the_schema(
        self, tmp_path: Path
    ) -> None:
        overlay = {"networkPolicy": {"broker": {"servicePorts": [8080]}}}

        result = _helm_template(tmp_path, overlay)

        assert result.returncode != 0
        assert "servicePorts" in result.stderr or "broker" in result.stderr


def _cidrs(policies: dict[str, dict[str, Any]]) -> list[str]:
    """Every ipBlock cidr (and except entry) in the broker policy."""
    cidrs: list[str] = []
    for direction in ("egress", "ingress"):
        for rule in policies["af-mcp-platform-broker"]["spec"].get(direction, []):
            for peer in rule.get("to", []) + rule.get("from", []):
                block = peer.get("ipBlock")
                if block:
                    cidrs += [block["cidr"], *block.get("except", [])]
    return cidrs


class TestIpFamilies:
    def test_both_families_render_a_block_each_by_default(self, tmp_path: Path) -> None:
        overlay = {
            "networkPolicy": {
                "egress": {
                    "external": {"exceptCidrs": ["192.0.2.0/23", "2001:db8::/64"]}
                }
            }
        }

        cidrs = _cidrs(_policies(tmp_path, overlay))

        assert "0.0.0.0/0" in cidrs
        assert "::/0" in cidrs

    def test_ipv4_only_renders_no_ipv6_address_anywhere(self, tmp_path: Path) -> None:
        overlay = {
            "networkPolicy": {
                "ipFamilies": ["IPv4"],
                "egress": {
                    "external": {"exceptCidrs": ["192.0.2.0/23", "2001:db8::/64"]}
                },
            }
        }

        result = _helm_template(tmp_path, overlay)

        assert result.returncode == 0, result.stderr
        policies = _policies(tmp_path, overlay)
        assert not any(":" in c for c in _cidrs(policies))
        assert "192.0.2.0/23" in _cidrs(policies)
        assert "2001:db8::/64" not in result.stdout

    def test_ipv6_only_renders_no_ipv4_cidr_anywhere(self, tmp_path: Path) -> None:
        overlay = {
            "networkPolicy": {
                "ipFamilies": ["IPv6"],
                "egress": {
                    "external": {"exceptCidrs": ["192.0.2.0/23", "2001:db8::/64"]}
                },
            }
        }

        policies = _policies(tmp_path, overlay)

        cidrs = _cidrs(policies)
        assert cidrs
        assert all(":" in c for c in cidrs)
        assert "2001:db8::/64" in cidrs

    @pytest.mark.parametrize(
        "families",
        [[], ["IPv4", "IPv4"], ["IPv5"]],
        ids=["empty", "duplicate", "unknown"],
    )
    def test_schema_rejects_bad_family_lists(
        self, tmp_path: Path, families: list[str]
    ) -> None:
        result = _helm_template(tmp_path, {"networkPolicy": {"ipFamilies": families}})

        assert result.returncode != 0
        assert "ipFamilies" in result.stderr

    def test_shared_state_cidr_in_a_disabled_family_is_refused(
        self, tmp_path: Path
    ) -> None:
        overlay = {
            "networkPolicy": {"ipFamilies": ["IPv6"]},
            "broker": {
                "sharedState": {
                    "networkPolicy": {"cidr": "203.0.113.0/24", "port": 6379}
                }
            },
        }

        result = _helm_template(tmp_path, overlay)

        assert result.returncode != 0
        assert "203.0.113.0/24" in result.stderr


class TestGenerateSwitch:
    def test_without_generation_only_dns_and_extra_egress_remain(
        self, tmp_path: Path
    ) -> None:
        extra = {
            "to": [{"ipBlock": {"cidr": "203.0.113.0/24"}}],
            "ports": [{"protocol": "TCP", "port": 6443}],
        }
        overlay = {
            "networkPolicy": {"egress": {"generate": False, "extraEgress": [extra]}}
        }

        policies = _policies(tmp_path, overlay)

        egress = policies["af-mcp-platform-broker"]["spec"]["egress"]
        assert [r.get("to") for r in egress] == [None, extra["to"]]
        assert policies["af-mcp-platform-broker"]["spec"]["ingress"]

    def test_without_generation_in_cluster_urls_need_no_endpoints(
        self, tmp_path: Path
    ) -> None:
        overlay = {
            "aggregator": {"services": [_service("http://svc.backend.svc:8080/mcp")]},
            "networkPolicy": {"egress": {"generate": False}},
        }

        assert _helm_template(tmp_path, overlay).returncode == 0


class TestIngressSources:
    def test_default_sources_are_generic_and_name_no_facility_namespace(
        self, tmp_path: Path
    ) -> None:
        spec = _policies(tmp_path, {})["af-mcp-platform-broker"]["spec"]

        namespaces = {
            p["namespaceSelector"]["matchLabels"][_NAMESPACE_LABEL]
            for rule in spec["ingress"]
            for p in rule["from"]
            if "namespaceSelector" in p
        }
        assert namespaces == {"ingress-nginx", "monitoring"}

    def test_sources_replace_the_defaults(self, tmp_path: Path) -> None:
        sources = [
            {
                "namespaceSelector": {"matchLabels": {_NAMESPACE_LABEL: "prom"}},
                "podSelector": {"matchLabels": {"app": "prometheus"}},
                "ports": [9090],
            }
        ]
        overlay = {"networkPolicy": {"ingress": {"broker": {"sources": sources}}}}

        ingress = _policies(tmp_path, overlay)["af-mcp-platform-broker"]["spec"][
            "ingress"
        ]

        assert ingress[0] == {
            "from": [
                {
                    "namespaceSelector": sources[0]["namespaceSelector"],
                    "podSelector": sources[0]["podSelector"],
                }
            ],
            "ports": [{"protocol": "TCP", "port": 9090}],
        }
        assert len(ingress) == 2  # the source and the chart's helm-test pod

    def test_extra_ingress_is_appended_verbatim_to_each_policy(
        self, tmp_path: Path
    ) -> None:
        extra = {
            "from": [{"ipBlock": {"cidr": "203.0.113.0/24"}}],
            "ports": [{"protocol": "TCP", "port": 8080}],
        }
        overlay = {
            "networkPolicy": {
                "ingress": {
                    "broker": {"extraIngress": [extra]},
                    "portal": {"extraIngress": [extra]},
                }
            }
        }

        policies = _policies(tmp_path, overlay)

        assert policies["af-mcp-platform-broker"]["spec"]["ingress"][-1] == extra
        assert policies["af-mcp-platform-portal"]["spec"]["ingress"][-1] == extra

    def test_portal_sources_default_to_the_ingress_controller_on_the_portal_port(
        self, tmp_path: Path
    ) -> None:
        ingress = _policies(tmp_path, {})["af-mcp-platform-portal"]["spec"]["ingress"]

        assert [r["ports"] for r in ingress] == [[{"protocol": "TCP", "port": 8081}]]

    def test_source_without_a_selector_is_rejected_by_the_schema(
        self, tmp_path: Path
    ) -> None:
        overlay = {
            "networkPolicy": {"ingress": {"broker": {"sources": [{"ports": [8080]}]}}}
        }

        result = _helm_template(tmp_path, overlay)

        assert result.returncode != 0
        assert "sources" in result.stderr
