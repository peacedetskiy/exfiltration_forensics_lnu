import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, TCP
from collections import Counter
from statistics import mean, variance
from math import log2
from datetime import datetime
from collections import defaultdict
import csv
import sys
import os


# Optional GeoIP
try:
    import geoip2.database
    country_reader = geoip2.database.Reader("GeoLite2-Country.mmdb")
    asn_reader = geoip2.database.Reader("GeoLite2-ASN.mmdb")
    HAS_GEOIP = True
    print("GeoIP enabled")
except:
    HAS_GEOIP = False
    print("GeoIP disabled (optional)")

# -------------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------------
def entropy(s):
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c/length) * log2(c/length) for c in freq.values())

def longest_word(qname):
    words = ''.join(c if c.isalpha() else ' ' for c in qname).split()
    return max((len(w) for w in words), default=0)

def get_sld(qname):
    labels = [l for l in qname.rstrip('.').split('.') if l]
    return labels[-2] if len(labels) >= 2 else ''

def decode_name(name):
    if isinstance(name, bytes):
        return name.decode('utf-8', errors='ignore').rstrip('.')
    return str(name).rstrip('.')

# -------------------------------------------------------------------
# Stateless extraction per DNS query
# -------------------------------------------------------------------
def extract_stateless(pkt):
    if not pkt.haslayer(DNSQR):
        return None

    qname = decode_name(pkt[DNSQR].qname)
    if not qname or qname == '.':
        return None

    timestamp = datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    labels_list = [l for l in qname.split('.') if l]
    n_labels = len(labels_list)
    subdomain_flag = 1 if n_labels > 2 else 0
    subdomain_part = '.'.join(labels_list[:-2]) if subdomain_flag else ''

    return {
        'timestamp': timestamp,
        'FQDN_count': len(qname),
        'subdomain_length': len(subdomain_part),
        'upper': sum(1 for c in qname if c.isupper()),
        'lower': sum(1 for c in qname if c.islower()),
        'numeric': sum(1 for c in qname if c.isdigit()),
        'entropy': round(entropy(qname), 10),
        'special': sum(1 for c in qname if c in '-_'),
        'labels': n_labels,
        'labels_max': max((len(l) for l in labels_list), default=0),
        'labels_average': round(sum(len(l) for l in labels_list)/n_labels, 10) if n_labels else 0,
        'longest_word': longest_word(qname),
        'sld': get_sld(qname),
        'len': len(qname),
        'subdomain': subdomain_flag
    }

# -------------------------------------------------------------------
# Stateful extraction per DNS packet
# -------------------------------------------------------------------
def extract_stateful(pkt, ip_to_domains):
    if not pkt.haslayer(DNS):
        return None
    dns_layer = pkt[DNS]

    # Collect all RR records in the packet
    all_rrs = []
    try:
        for i in range(dns_layer.ancount):
            all_rrs.append(dns_layer.an[i])
        for i in range(dns_layer.nscount):
            all_rrs.append(dns_layer.ns[i])
        for i in range(dns_layer.arcount):
            all_rrs.append(dns_layer.ar[i])
    except Exception:
        pass

    if not all_rrs:
        return None

    # Count RR types
    freq_map = {1:'A',2:'NS',5:'CNAME',6:'SOA',10:'NULL',12:'PTR',13:'HINFO',
                15:'MX',16:'TXT',28:'AAAA',33:'SRV',41:'OPT'}
    type_cnt = Counter()
    for rr in all_rrs:
        if hasattr(rr,'type'):
            type_cnt[rr.type] += 1

    freq_dict = {f"{freq_map.get(t,'OTHER')}_frequency": type_cnt.get(t,0) for t in freq_map}

    rr_types_set = {freq_map.get(t,'OTHER') for t in type_cnt if type_cnt[t] > 0}
    rr_count = len(all_rrs)

    rr_names = []
    for rr in all_rrs:
        try:
            name = decode_name(rr.rrname)
            if name:
                rr_names.append(name)
        except:
            continue

    rr_name_entropy = round(mean([entropy(n) for n in rr_names]), 10) if rr_names else 0.0
    rr_name_length = round(mean(len(n) for n in rr_names), 10) if rr_names else 0.0

    ips = set()
    for rr in all_rrs:
        try:
            if rr.type in (1,28):
                rdata = rr.rdata
                if isinstance(rdata,(str,bytes)):
                    ips.add(str(rdata))
        except:
            continue

    countries = set()
    asns = set()
    if HAS_GEOIP and ips:
        for ip in ips:
            try:
                countries.add(country_reader.country(ip).country.iso_code)
                asns.add(str(asn_reader.asn(ip).autonomous_system_number))
            except:
                continue

    shared_domains = {dom for ip in ips for dom in ip_to_domains.get(ip,set())}

    ttls = [rr.ttl for rr in all_rrs if hasattr(rr,'ttl')]
    unique_ttl_str = str(sorted(set(ttls))) if ttls else '[]'
    ttl_mean_val = mean(ttls) if ttls else 0.0
    ttl_var_val = variance(ttls) if len(ttls) > 1 else 0.0

    a_records = type_cnt.get(1,0)
    rr_ratio = a_records / (a_records + type_cnt.get(28,0)) if (a_records + type_cnt.get(28,0)) > 0 else 0.0

    return {
        'rr': round(rr_ratio, 10),
        **freq_dict,
        'rr_type': str(rr_types_set),
        'rr_count': rr_count,
        'rr_name_entropy': rr_name_entropy,
        'rr_name_length': rr_name_length,
        'distinct_ns': type_cnt.get(2,0),
        'distinct_ip': len(ips),
        'unique_country': str(countries),
        'unique_asn': str(asns),
        'distinct_domains': str(shared_domains),
        'reverse_dns': 'unknown',
        'a_records': a_records,
        'unique_ttl': unique_ttl_str,
        'ttl_mean': round(ttl_mean_val, 10),
        'ttl_variance': round(ttl_var_val, 10)
    }

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
def features_extraction(pcap_path):
    print(f"Loading {pcap_path} ...")
    packets = scapy.rdpcap(pcap_path)

    # Filter DNS packets
    dns_packets = [p for p in packets if p.haslayer(DNS) and (
        (p.haslayer(UDP) and (p[UDP].sport==53 or p[UDP].dport==53)) or
        (p.haslayer(TCP) and (p[TCP].sport==53 or p[TCP].dport==53))
    )]

    print(f"Found {len(dns_packets):,} DNS packets (port 53)")

    # Build IP → domains map
    ip_to_domains = defaultdict(set)
    for p in dns_packets:
        if p.haslayer(DNSQR) and p.haslayer(DNSRR):
            try:
                qname = decode_name(p[DNSQR].qname)
                domain = '.'.join(qname.split('.')[-2:]) if '.' in qname else qname
                for rr in getattr(p[DNS],'an',[])+getattr(p[DNS],'ns',[])+getattr(p[DNS],'ar',[]):
                    try:
                        if rr.type in (1,28):
                            ip_to_domains[str(rr.rdata)].add(domain)
                    except:
                        continue
            except:
                continue

    # Stateless per-packet
    stateless_rows = [r for p in dns_packets if (r:=extract_stateless(p))]
    print(f"Stateless rows: {len(stateless_rows)}")

    # Stateful per-packet
    stateful_rows = [r for p in dns_packets if (r:=extract_stateful(p, ip_to_domains))]
    print(f"Stateful rows: {len(stateful_rows)}")

    # Save CSVs
    base = os.path.splitext(pcap_path)[0]

    if stateless_rows:
        with open(f"{base}_stateless.csv", 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=stateless_rows[0].keys())
            w.writeheader()
            w.writerows(stateless_rows)
        print(f"Stateless → {base}_stateless.csv")

    if stateful_rows:
        with open(f"{base}_stateful.csv", 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=stateful_rows[0].keys())
            w.writeheader()
            w.writerows(stateful_rows)
        print(f"Stateful → {base}_stateful.csv")

    print("Done! CSVs per packet are ready for LGBM.")
