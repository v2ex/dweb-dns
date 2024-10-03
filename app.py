import base64
import copy
import json
import re
import time
import traceback

import dns.message
import dns.name
import flask
import redis
import requests
from rq import Queue
from flask import Flask, make_response, request
from markupsafe import escape

import config

app = Flask(__name__)
q = Queue("dweb", connection=redis.Redis())


def make_rr(simple, rdata):
    csimple = copy.copy(simple)
    rdata_text = rdata.to_text()
    if rdata_text.startswith('"') and rdata_text.endswith('"'):
        rdata_text = rdata_text[1:-1]
    csimple["data"] = rdata_text
    return csimple


def flatten_rrset(rrs):
    simple = {
        "name": str(rrs.name),
        "type": rrs.rdtype,
    }
    if len(rrs) > 0:
        simple["TTL"] = rrs.ttl
        return [make_rr(simple, rdata) for rdata in rrs]
    else:
        return [simple]


def to_doh_simple(message):
    simple = {"Status": int(message.rcode())}
    for f in dns.flags.Flag:
        if f != dns.flags.Flag.AA and f != dns.flags.Flag.QR:
            # DoH JSON doesn't need AA and omits it.  DoH JSON is only
            # used in replies so the QR flag is implied.
            simple[f.name] = (message.flags & f) != 0
    for i, s in enumerate(message.sections):
        k = dns.message.MessageSection.to_text(i).title()
        simple[k] = []
        for rrs in s:
            simple[k].extend(flatten_rrset(rrs))
    # we don't encode the ecs_client_subnet field
    response = flask.Response(json.dumps(simple, indent=2) + "\n")
    response.headers.set("Content-Type", "application/dns-json")
    response.headers.set("Cloudflare-CDN-Cache-Control", f"public, max-age=${config.cache_ttl}")
    return response


def make_empty_message(name="", t=dns.rdatatype.TXT):
    name = dns.name.from_text(name)
    return dns.message.make_response(dns.message.make_query(name, t))


def output(message, ct="application/dns-json"):
    if ct == "application/dns-message":
        response = make_response(message.to_wire())
        response.headers.set("Content-Type", "application/dns-message")
        response.headers.set("Cloudflare-CDN-Cache-Control", f"public, max-age=${config.cache_ttl}")
        return response
    elif ct == "application/x-javascript":
        return to_doh_simple(message)
    elif ct == "application/dns-json":
        return to_doh_simple(message)
    else:
        return to_doh_simple(message)
    

def sol_resolve(name):
    sns_sdk = "https://sns-sdk-proxy.bonfida.workers.dev"
    # try: /record-v2/{name}/IPNS
    query = sns_sdk + "/record-v2/" + name + "/IPNS"
    r = requests.get(query)
    if r.status_code == 200:
        o = r.json()
        if "result" in o and o["result"] is not None and "deserialized" in o["result"]:
            ipns = o["result"]["deserialized"]
            if ipns.startswith("k51") or ipns.startswith("k2"):
                return "dnslink=" + handle_ipns(ipns)
            if ipns.startswith("ipns://"):
                ipns = str(ipns[len("ipns://") :])
                return "dnslink=" + handle_ipns(ipns)
    # try: /domain-data/{name}
    query = sns_sdk + "/domain-data/" + name
    r = requests.get(query)
    if r.status_code == 200:
        o = r.json()
        if "result" in o and o["result"] is not None:
            result = o["result"]
            try:
                decoded = base64.b64decode(result)
                # Discard non-UTF-8 parts and use the usable part of the string
                decoded_str = decoded.decode('utf-8', errors='ignore')
                # Use regex to find ipns=
                ipns = re.compile(r"ipns=(k51[a-zA-Z0-9]{59})").search(decoded_str)
                if ipns is not None:
                    return "dnslink=" + handle_ipns(ipns.group(1))
            except UnicodeDecodeError as e:
                print(f"UnicodeDecodeError: {e}", flush=True)
    return None


def dotbit_resolve(name):
    indexer = "https://indexer-v1.did.id/v1/account/records"
    payload = {"account": name}
    r = requests.post(indexer, json=payload)
    if r.status_code == 200:
        o = r.json()
        print(r.text, flush=True)
        if "data" in o and o["data"] is not None and "records" in o["data"]:
            records = o["data"]["records"]
            for record in records:
                if record["key"] == "dweb.ipns":
                    return "dnslink=" + handle_ipns(record["value"])
                if record["key"] == "dweb.ipfs":
                    return "dnslink=/ipfs/" + record["value"]
    return None


def ens_resolve(name):
    resolver = "https://api.planetable.xyz/ens/resolve/"
    r = requests.get(resolver + name)
    if r.status_code == 200:
        o = r.json()
        if (
            "contentHash" in o
            and o["contentHash"] is not None
            and o["contentHash"] != ""
        ):
            content_hash = o["contentHash"]
            if content_hash.startswith("ipfs://"):
                return "dnslink=/ipfs/" + content_hash[len("ipfs://") :]
            if content_hash.startswith("ipns://"):
                ipns = str(content_hash[len("ipns://") :])
                result = handle_ipns(ipns)
                return "dnslink=" + result
    return None


@app.route("/dns-query", methods=["GET", "POST"])
def dns_query():
    if request.data:
        try:
            question = dns.message.from_wire(request.data)
            if question.question:
                q = question.question[0]
                print(str(q), flush=True)
                if q.rdtype == 16:
                    name = str(q.name)
                    if name.endswith(".bit."):
                        name = name[0:-1]
                    if name.endswith(".sol."):
                        name = name[0:-1]
                    if name.endswith(".eth."):
                        name = name[0:-1]
                    if name.startswith("_dnslink."):
                        name = name[len("_dnslink.") :]
                    result = None
                    if name.endswith(".bit"):
                        result = dotbit_resolve(name)
                    if name.endswith(".sol"):
                        result = sol_resolve(name)
                    if name.endswith(".eth"):
                        result = ens_resolve(name)
                    if result is not None:
                        print("Resolved: " + name + " -> " + result, flush=True)
                        response = dns.message.make_response(question)
                        response.answer.append(
                            dns.rrset.from_text(
                                q.name,
                                config.cache_ttl,
                                dns.rdataclass.IN,
                                dns.rdatatype.TXT,
                                result,
                            )
                        )
                        return output(response, "application/dns-message")
            return output(make_empty_message())
        except Exception as e:
            print("Error: " + str(e), flush=True)
            print(traceback.format_exc(), flush=True)
            return output(make_empty_message())
    # get type
    t = request.values.get("type")
    if not t:
        # set default type to TXT
        t = dns.rdatatype.TXT
    try:
        t = dns.rdatatype.from_text(dns.rdatatype.to_text(int(t)))
    except:
        t = dns.rdatatype.TXT
    if t not in [dns.rdatatype.TXT, dns.rdatatype.A, dns.rdatatype.AAAA]:
        t = dns.rdatatype.TXT

    # get ct (content-type)
    ct = request.values.get("ct")
    ct_accept = request.headers.get("Accept")
    if not ct and not ct_accept:
        # set default ct to json
        ct = "application/x-javascript"
    elif not ct and ct_accept:
        ct = ct_accept
    else:
        if ct not in [
            "application/dns-message",
            "application/x-javascript",
            "application/dns-json",
        ]:
            ct = "application/x-javascript"

    # name is required
    name = request.values.get("name")
    if not name:
        print("Please provide a name", flush=True)
        return output(make_empty_message(t=t), ct)

    name = name.lower()
    if name.endswith(".bit."):
        name = name[0:-1]
    if name.endswith(".sol."):
        name = name[0:-1]

    if t != dns.rdatatype.TXT:
        print("Type is not TXT: " + str(t), flush=True)
        return output(make_empty_message(name, t=t), ct)

    result = None
    if name.endswith(".bit"):
        result = dotbit_resolve(name)
    if name.endswith(".sol"):
        result = sol_resolve(name)
    if name.endswith(".eth"):
        result = ens_resolve(name)
    if result is not None:
        print("Resolved: " + name + " -> " + result, flush=True)
        response = dns.message.make_response(dns.message.make_query(name, t))
        if ct == "application/dns-message":
            response.answer.append(
                dns.rrset.from_text(
                    name + ".", config.cache_ttl, dns.rdataclass.IN, dns.rdatatype.TXT, result
                )
            )
        else:
            response.answer.append(
                dns.rrset.from_text(
                    name, config.cache_ttl, dns.rdataclass.IN, dns.rdatatype.TXT, result
                )
            )
        return output(response, ct)
    print("Unsupported: name=" + str(name) + " / t=" + str(t), flush=True)
    return output(make_empty_message(name, t=t), ct)


def resolve_ipns(ipns: str) -> str:
    rc = redis.Redis(host="localhost", port=6379, db=0)
    r_key = "ipns:" + ipns + ":results"
    print("Resolving IPNS: " + ipns, flush=True)
    url = config.ipfs_api_server + "api/v0/name/resolve?arg=" + ipns + "&recursive=true&stream=true&nocache=true"
    try:
        print("POST: " + url, flush=True)
        r = requests.post(url)
        if r.status_code == 200:
            lines = r.text.split("\n")
            for line in lines:
                if line.startswith("{"):
                    o = json.loads(line)
                    existing = rc.zscore(r_key, o["Path"])
                    if existing is None:
                        print("Adding: " + o["Path"], flush=True)
                        rc.zadd(r_key, {o["Path"]: int(time.time())}, nx=True)
                        return o["Path"]
            latest = rc.zrevrange(r_key, 0, 0)
            if latest is not None and len(latest) > 0:
                return latest[0].decode("utf-8")
        else:
            print("Error: " + str(r.status_code), flush=True)
            print("Error: " + str(r.text), flush=True)
        return "/ipns/" + ipns
    except Exception as e:
        print("Error: " + str(e), flush=True)
        return "/ipns/" + ipns


def handle_ipns(ipns: str) -> str:
    r = redis.Redis(host="localhost", port=6379, db=0)
    r_key = "ipns:" + ipns + ":results"
    latest = r.zrevrange(r_key, 0, 0)
    if latest is not None and len(latest) > 0:
        q.enqueue(revalidate_ipns, ipns)
        return latest[0].decode("utf-8")
    else:
        return resolve_ipns(ipns)


def revalidate_ipns(ipns: str):
    value = resolve_ipns(ipns)
    print("Revalidated: " + ipns + " -> " + value, flush=True)