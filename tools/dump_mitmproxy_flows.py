#!/usr/bin/env python3
"""Dump mitmproxy flow objects to understand their structure for test mocks.

Runs mitmproxy as an explicit proxy (no root/iptables needed) and dumps the
attributes our MitmproxyAddon accesses for each hook.

Usage:
    # Start the dumper (HTTP proxy on :8080, DNS on :8053):
    uv run --extra proxy python tools/dump_mitmproxy_flows.py

    # In another terminal, generate flows:
    curl -x http://localhost:8080 http://example.com           # HTTP request
    curl -x http://localhost:8080 -k https://example.com       # HTTPS (MITM)
    dig @127.0.0.1 -p 8053 example.com                        # DNS

Output is JSON, one object per hook invocation, separated by ---.
"""

import asyncio
import json
import sys

from mitmproxy import dns, http, tcp, tls
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster


def _dump(hook_name: str, attrs: dict, types: dict) -> None:
    """Print a structured dump."""
    print(json.dumps({"hook": hook_name, "attrs": attrs, "types": types},
                     indent=2, default=str))
    print("---")
    sys.stdout.flush()


def _type_path(obj, *attrs):
    """Walk an attribute path and return the type at each step."""
    result = {}
    current = obj
    path = ""
    for attr in attrs:
        path = f"{path}.{attr}" if path else attr
        try:
            current = getattr(current, attr)
            result[path] = type(current).__qualname__
        except Exception as e:
            result[path] = f"<error: {e}>"
            break
    return result


class FlowDumper:
    """Mitmproxy addon that dumps the flow attributes our addon accesses."""

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        attrs = {
            "context.client.peername": data.context.client.peername,
            "context.server.address": data.context.server.address,
            "client_hello.sni": data.client_hello.sni,
        }
        types = {
            "data": type(data).__qualname__,
            **_type_path(data, "context"),
            **_type_path(data, "context", "client"),
            **_type_path(data, "context", "server"),
            **_type_path(data, "client_hello"),
            # Settable attrs our addon uses:
            "data.ignore_connection": type(data.ignore_connection).__qualname__,
        }
        _dump("tls_clienthello", attrs, types)

    def request(self, flow: http.HTTPFlow) -> None:
        attrs = {
            "client_conn.peername": flow.client_conn.peername,
            "server_conn.address": flow.server_conn.address,
            "request.pretty_url": flow.request.pretty_url,
            "request.method": flow.request.method,
            "request.scheme": flow.request.scheme,
            "request.host": flow.request.host,
        }
        types = {
            "flow": type(flow).__qualname__,
            **_type_path(flow, "client_conn"),
            **_type_path(flow, "server_conn"),
            **_type_path(flow, "request"),
        }
        _dump("request", attrs, types)

    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        attrs = {
            "client_conn.peername": flow.client_conn.peername,
            "server_conn.address": flow.server_conn.address,
        }
        types = {
            "flow": type(flow).__qualname__,
            **_type_path(flow, "client_conn"),
            **_type_path(flow, "server_conn"),
        }
        _dump("tcp_start", attrs, types)

    def dns_request(self, flow: dns.DNSFlow) -> None:
        questions = []
        for q in flow.request.questions:
            questions.append({
                "name": q.name, "type": q.type, "class_": q.class_,
            })
        attrs = {
            "client_conn.peername": flow.client_conn.peername,
            "flow.id": flow.id,
            "request.id": flow.request.id,
            "request.questions": questions,
        }
        types = {
            "flow": type(flow).__qualname__,
            **_type_path(flow, "request"),
            "question": type(flow.request.questions[0]).__qualname__ if flow.request.questions else None,
        }
        _dump("dns_request", attrs, types)

    def dns_response(self, flow: dns.DNSFlow) -> None:
        if not flow.response:
            return
        answers = []
        for a in flow.response.answers:
            entry = {"name": a.name, "type": a.type}
            if hasattr(a, "ttl"):
                entry["ttl"] = a.ttl
            if a.type == 1:
                entry["ipv4_address"] = str(a.ipv4_address)
                entry["data_hex"] = a.data.hex()
            elif a.type == 28:
                entry["ipv6_address"] = str(a.ipv6_address)
                entry["data_hex"] = a.data.hex()
            if a.type == 5:  # CNAME
                entry["data_hex"] = a.data.hex()
            answers.append(entry)
        attrs = {
            "flow.id": flow.id,
            "request.questions[0].name": (
                flow.request.questions[0].name if flow.request.questions else None
            ),
            "response.answers": answers,
        }
        types = {
            "response": type(flow.response).__qualname__,
            "answer": type(flow.response.answers[0]).__qualname__ if flow.response.answers else None,
        }
        _dump("dns_response", attrs, types)

    def tls_failed_client(self, data: tls.TlsData) -> None:
        attrs = {
            "context.client.peername": data.context.client.peername,
            "context.server.address": data.context.server.address,
            "context.client.sni": data.context.client.sni,
        }
        types = {
            "data": type(data).__qualname__,
        }
        _dump("tls_failed_client", attrs, types)


async def main():
    opts = Options(
        mode=["regular", "dns@8053"],
        listen_port=8080,
        showhost=True,
    )
    master = DumpMaster(opts)
    master.addons.add(FlowDumper())

    print("Flow dumper running:", file=sys.stderr)
    print("  HTTP/HTTPS proxy:  localhost:8080", file=sys.stderr)
    print("  DNS:               localhost:8053", file=sys.stderr)
    print("", file=sys.stderr)
    print("Generate flows with:", file=sys.stderr)
    print("  curl -x http://localhost:8080 http://example.com", file=sys.stderr)
    print("  curl -x http://localhost:8080 -k https://example.com", file=sys.stderr)
    print("  dig @127.0.0.1 -p 8053 example.com", file=sys.stderr)
    print("", file=sys.stderr)

    await master.run()


if __name__ == "__main__":
    asyncio.run(main())
