import json
import os
import shutil
import socket
import struct
import subprocess
import threading

from tailscale_ops import entry, entry_dns, firewall, guard, scripts, wgkey
from tailscale_ops import site as sitemod
from tailscale_ops.control import Deployment
from tailscale_ops.phone import Phones, clash_yaml, phone_hosts, wg_conf
from tailscale_ops.procedure import StepError
from tailscale_ops.remote import Result
from tests.helpers import FakeRunner, TempDirTest, bash, example_text
from tests.test_control import FakeOps, responses

ENTRY = (
    ("stun_port = 3478\n", "stun_port = 3478\nentry_port = 51820\n"),
    ('listen_ipv4 = "203.0.113.20"\nport = 9443\nstun_port = 3478\n',
     'listen_ipv4 = "203.0.113.20"\nport = 9443\nstun_port = 3478\nentry_port = 51821\n'),
)
# The control hosts are the line's ends, as on a small site.
ON_CONTROL = (('initiator = "cn-gateway"', 'initiator = "cn-control"'),
              ('responder = "ovs-line"', 'responder = "ovs-control"'))
ENTRY_PUB = "E" * 43 + "="
NFT_DROPS = json.dumps({"nftables": [
    {"chain": {"family": "inet", "table": "phones", "name": "forward", "hook": "forward", "policy": "drop"}},
    {"chain": {"family": "inet", "table": "guard", "name": "input", "hook": "input", "policy": "accept"}},
    {"rule": {"family": "inet", "table": "guard", "chain": "input", "expr": [{"drop": None}]}},
    {"chain": {"family": "inet", "table": "tn_entry", "name": "forward", "hook": "forward", "policy": "accept"}},
    {"rule": {"family": "inet", "table": "tn_entry", "chain": "forward", "expr": [{"drop": None}]}},
]})
CHECK_OUTPUT = (f"TN-FACT forward=1\nTN-BEGIN nft\n{NFT_DROPS}\nTN-END nft\nTN-BEGIN legacy-FORWARD\nTN-END legacy-FORWARD\n"
                "TN-BEGIN legacy-INPUT\n-P INPUT DROP\nTN-END legacy-INPUT\nentry checks passed; nothing was changed\n")


def nodes_json(*pairs):
    return json.dumps([{"id": i, "given_name": name, "ip_addresses": [ip, "fd7a:115c:a1e0::9"]}
                       for i, (name, ip) in enumerate(pairs, 1)]) + "\n"


class KeyTest(TempDirTest):
    def test_rfc7748_vectors(self):
        h = bytes.fromhex
        k = h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        self.assertEqual(wgkey.x25519(k, u).hex(), "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        alice = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        bob = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        a_pub, b_pub = wgkey.x25519(alice, wgkey.BASE), wgkey.x25519(bob, wgkey.BASE)
        self.assertEqual(a_pub.hex(), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        self.assertEqual(wgkey.x25519(alice, b_pub), wgkey.x25519(bob, a_pub))

    def test_keys_look_like_wg(self):
        private = wgkey.private_key()
        self.assertEqual((len(private), len(wgkey.public_key(private))), (44, 44))
        self.assertNotEqual(private, wgkey.private_key())
        with self.assertRaises(ValueError):
            wgkey.public_key("AAAA")


class EntrySiteTest(TempDirTest):
    def test_fields(self):
        site = self.load_site(example_text(*ENTRY))
        self.assertEqual([r.entry_port for r in site.entry_regions()], [51820, 51821])
        self.assertEqual((site.entry_ipv4, site.entry_address), ("10.255.254.0/24", "10.255.254.1"))
        self.assertEqual(self.load_site(name="plain").entry_regions(), [])

    def test_validation(self):
        for pairs, message in (
            ((("stun_port = 3478\n", "stun_port = 3478\nentry_port = 3478\n"),), "is the STUN port"),
            ((("tailscale_port = 41641", "tailscale_port = 51821"), *ENTRY), "entry_port on this host"),
            ((*ENTRY, ('dns_suffix = "tailnet.internal"', 'dns_suffix = "tailnet.internal"\nentry_ipv4 = "10.255.1.0/24"')),
             "overlaps regions.cn.alias_ipv4"),
            ((*ENTRY, ('dns_suffix = "tailnet.internal"', 'dns_suffix = "tailnet.internal"\nentry_ipv4 = "100.64.200.0/24"')),
             "private range outside 100.64.0.0/10"),
            ((*ENTRY, ('dns_suffix = "tailnet.internal"', 'dns_suffix = "tailnet.internal"\nentry_ipv4 = "10.255.250.0/30"')),
             "too small"),
            ((*ON_CONTROL, ENTRY[0], ENTRY[1], ("entry_port = 51821", "entry_port = 11011")), "is line line1's port"),
        ):
            with self.subTest(message=message), self.assertRaises(sitemod.SiteError) as cm:
                sitemod.load(self.make_site_dir(example_text(*pairs), name=f"v{abs(hash(message))}"),
                             known_host=lambda a: True)
            self.assertIn(message, str(cm.exception))

    def test_phones_file_is_read_and_blocked_from_the_repository(self):
        d = self.make_site_dir(example_text(*ENTRY))
        sitemod.write_phones(d, {"iphone": {"address": "10.255.254.2", "public_key": ENTRY_PUB}})
        self.assertEqual(sitemod.load(d, known_host=lambda a: True).phones["iphone"]["address"], "10.255.254.2")
        self.assertIn("phones.json", guard.scan_path("x/phones.json"))


class EntryRenderTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site(example_text(*ENTRY, *ON_CONTROL))
        self.site.phones = {"iphone": {"address": "10.255.254.2", "public_key": ENTRY_PUB},
                            "ipad": {"address": "10.255.254.3", "public_key": "D" * 43 + "="}}
        self.cn, self.ovs = self.site.regions["cn"], self.site.regions["ovs"]

    def test_conf(self):
        text = entry.conf(self.site, self.cn)
        self.assertTrue(text.startswith("# tailnet-ops entry region=cn\n[Interface]\nAddress = 10.255.254.1/24\n"
                                        "ListenPort = 51820\n"))
        self.assertIn("PostUp = wg set %i private-key /etc/wireguard/tn-entry.key", text)
        self.assertNotIn("PrivateKey", text)
        # Peers in name order, one /32 each.
        self.assertLess(text.index("# ipad"), text.index("# iphone"))
        self.assertIn(f"PublicKey = {ENTRY_PUB}\nAllowedIPs = 10.255.254.2/32", text)

    def test_nft_maps_the_other_region_and_allows_only_the_tailnets(self):
        text = entry.nft_rules(self.site, self.cn)
        self.assertIn('iifname "tn-entry" ip daddr 100.64.2.0/24 dnat ip prefix to ip daddr map '
                      '{ 100.64.2.0/24 : 10.255.2.0/24 }', text)
        self.assertIn('iifname "tn-entry" ip daddr != { 100.64.1.0/24, 10.255.2.0/24 } drop', text)
        self.assertIn('iifname "tn-entry" oifname != "tn-entry" masquerade', text)
        self.assertEqual(entry.phone_routes(self.site, self.ovs),
                         ["100.64.2.0/24", "100.64.1.0/24", "10.255.1.0/24", "10.255.254.1/32"])
        # Without a line there is nothing to map.
        alone = self.load_site(example_text(*ENTRY), name="alone")
        alone.lines = []
        self.assertNotIn("prerouting", entry.nft_rules(alone, alone.regions["cn"]))

    def test_accept_rules(self):
        found = entry.targets(Result(0, CHECK_OUTPUT))
        self.assertEqual([t.label() for t in found["forward"]], ["nft inet phones forward"])  # never our own table
        self.assertEqual([t.label() for t in found["input"]], ["nft inet guard input", "iptables-legacy INPUT"])
        text = entry.allow_script(self.site, self.ovs, found)
        self.assertEqual(text.splitlines()[1], "# tailnet-ops entry region=ovs")
        for rule in ('iifname "tn-entry" oifname "tailscale0"', 'iifname "tailscale0" oifname "tn-entry"',
                     'iifname "tn-entry" oifname "wg-line1"', 'iifname "wg-line1" oifname "tn-entry"',
                     "ip daddr 203.0.113.20 udp dport 51821", 'inet guard input iifname "tn-entry"'):
            self.assertIn(rule, text)
        self.assertIn("iptables-legacy -I INPUT 1 -d 203.0.113.20 -p udp --dport 51821", text)
        # A host that listens on every address accepts the port on every address.
        self.assertIn("insert rule inet guard input udp dport 51820 counter accept",
                      entry.allow_script(self.site, self.cn, found))
        p = subprocess.run(["sh", "-n"], input=text, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_scripts_parse_and_pass_shellcheck(self):
        found = entry.targets(Result(0, CHECK_OUTPUT))
        for r in (self.cn, self.ovs):
            prelude = scripts.control_prelude(self.site, r)
            for body in (entry.check(self.site, r), entry.start(self.site, r, found, "0"), entry.update_peers(self.site, r),
                         entry.rollback(self.site, r), entry.leftovers(self.site, r),
                         entry.status(self.site, r, "cn-control.cn.tailnet.internal")):
                script = scripts.wrap(prelude, body)
                p = subprocess.run([bash(), "-n"], input=script, capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stderr)
                if shutil.which("shellcheck"):
                    p = subprocess.run(["shellcheck", "-s", "bash", "-S", "warning", "-e", "SC2034", "-"],
                                       input=script, capture_output=True, text=True)
                    self.assertEqual(p.returncode, 0, p.stdout)

    def test_peer_sync_against_a_fake_wg(self):
        """The running interface ends with exactly the listed phones; the key file is only read."""
        stubs = self.tmp / "stubs"
        stubs.mkdir()
        log = self.tmp / "wg.log"
        (stubs / "wg").write_text(
            '#!/bin/sh\necho "$*" >> "$WG_LOG"\n'
            'case "$1 $3" in "show peers") printf "OLDPEER%s=\\n' + ENTRY_PUB + '\\n" "' + "O" * 35 + '" ;; esac\n'
            '[ "$1" = pubkey ] && echo ' + ENTRY_PUB + '\nexit 0\n')
        (stubs / "wg").chmod(0o755)
        key = self.tmp / "key"
        key.write_text("private\n")
        script = scripts.wrap(f'set -euo pipefail\nEIFACE=tn-entry\nEKEY={key}\n', entry.sync_peers(self.site))
        env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}", "WG_LOG": str(log)}
        p = subprocess.run([bash(), "-s"], input=script, capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        calls = log.read_text().splitlines()
        self.assertIn(f"set tn-entry peer OLDPEER{'O' * 35}= remove", calls)
        self.assertNotIn(f"set tn-entry peer {ENTRY_PUB} remove", calls)
        self.assertIn(f"set tn-entry peer {ENTRY_PUB} allowed-ips 10.255.254.2/32", calls)
        self.assertIn(f"set tn-entry peer {'D' * 43}= allowed-ips 10.255.254.3/32", calls)
        self.assertIn(f"TN-FACT pub={ENTRY_PUB}", p.stdout)


    def _update_peers(self, old_conf):
        """Run update_peers in bash against old_conf in a temp directory, with a stub wg."""
        wgdir = self.tmp / "wireguard"
        wgdir.mkdir(exist_ok=True)
        (wgdir / "tn-entry.conf").write_text(old_conf.replace("/etc/wireguard", str(wgdir)))
        (wgdir / "tn-entry.key").write_text("private\n")
        stubs = self.tmp / "stubs"
        stubs.mkdir(exist_ok=True)
        (stubs / "wg").write_text('#!/bin/sh\necho "$*" >> "$WG_LOG"\n[ "$1" = pubkey ] && echo ' + ENTRY_PUB + "\nexit 0\n")
        (stubs / "wg").chmod(0o755)
        prelude = 'set -euo pipefail\nREGION=cn\ndie() { echo "tn: $*" >&2; exit 1; }'
        script = scripts.wrap(prelude, entry.update_peers(self.site, self.cn)).replace("/etc/wireguard", str(wgdir))
        env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}", "WG_LOG": str(self.tmp / "wg.log")}
        p = subprocess.run([bash(), "-s"], input=script, capture_output=True, text=True, env=env)
        return p, (wgdir / "tn-entry.conf").read_text().replace(str(wgdir), "/etc/wireguard")

    def test_update_peers_adds_the_first_phone_without_a_restart(self):
        phones, self.site.phones = self.site.phones, {}
        empty = entry.conf(self.site, self.cn)
        self.site.phones = phones
        p, conf = self._update_peers(empty)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(conf.strip(), entry.conf(self.site, self.cn).strip())
        self.assertIn(f"TN-FACT pub={ENTRY_PUB}", p.stdout)

    def test_update_peers_refuses_an_other_interface(self):
        changed = entry.conf(self.site, self.cn).replace("ListenPort = 51820", "ListenPort = 51899")
        p, conf = self._update_peers(changed)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("differs outside its peers", p.stderr)
        self.assertEqual(conf, changed)


class EntryControlTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site(example_text(*ENTRY, *ON_CONTROL))
        self.out = []

    def dep(self, runner, region="cn"):
        return Deployment(self.site, region, runner=runner, ops=FakeOps(), out=self.out.append,
                          ssh_view=lambda h: {"user": "root", "hostname": h})

    def test_plan(self):
        text, _ = self.dep(None).plan_text()
        self.assertIn("Step 9/10  Phone entry", text)
        self.assertIn("Step 10/10  Verify", text)
        self.assertIn("runs the rollbacks of steps 9, 8, 6, 5, 4, 3, 2 in that order", text)
        self.assertIn("ENTRY_PORT=51820", text)
        self.assertIn("phone entry   udp 0.0.0.0:51820, WireGuard tn-entry 10.255.254.1/24", text)
        self.assertNotIn("Phone entry", Deployment(self.load_site(name="plain"), "cn").plan_text()[0])
        summary = self.dep(None).summary_text()
        self.assertIn("   9  Phone entry: WireGuard udp/51820, nft table tn_entry", summary)
        self.assertIn("  10  Check TLS, DERP and STUN", summary)

    def test_apply_checks_then_starts_with_the_chains_found(self):
        runner = FakeRunner({**responses(), "entry checks passed": CHECK_OUTPUT,
                             "private key: made on this host": f"TN-FACT pub={ENTRY_PUB}\n"})
        self.assertEqual(self.dep(runner).apply(yes=True), 0, "\n".join(self.out))
        sent = runner.scripts_for("cn-control")
        check = next(i for i, s in enumerate(sent) if "entry checks passed" in s)
        start = next(i for i, s in enumerate(sent) if "private key: made on this host" in s)
        self.assertLess(check, start)
        self.assertIn("insert rule inet phones forward", sent[start])
        self.assertIn("iptables-legacy -I INPUT 1 -p udp --dport 51820", sent[start])
        self.assertIn(f"entry public key {ENTRY_PUB}", "\n".join(self.out))

    def test_preflight_runs_the_entry_checks(self):
        runner = FakeRunner({**responses(), "entry checks passed": CHECK_OUTPUT})
        self.assertEqual(self.dep(runner).preflight(), 0, "\n".join(self.out))
        self.assertEqual(len(runner.calls), 2)
        self.assertIn("firewall: nft inet guard input could drop phone traffic", "\n".join(self.out))

    def test_rollback_starts_with_the_entry(self):
        runner = FakeRunner()
        self.assertEqual(self.dep(runner).rollback(yes=True), 0)
        first = runner.scripts_for("cn-control")[0]
        self.assertIn('systemctl disable --now "wg-quick@$EIFACE"', first)


class Hosts(FakeRunner):
    """Both control hosts: Headscale's node lists, and entries that are there unless `absent`."""

    def __init__(self, absent=()):
        super().__init__()
        self.absent = set(absent)

    def run(self, host, script, args=(), privileged=False, check=True, echo=True, secret=False):
        super().run(host, script, args, privileged, check, echo, secret)
        if "nodes list -o json" in script:
            pairs = [("cn-control", "100.64.1.1"), ("web", "100.64.1.5")] if host == "cn-control" else \
                [("ovs-control", "100.64.2.1"), ("web", "100.64.2.9")]
            return Result(0, nodes_json(*pairs) + "TN-FACT names_keeper=no\n")
        if "differs outside its peers" in script:
            return Result(0, "TN-FACT entry=absent\n" if host in self.absent else f"TN-FACT pub={ENTRY_PUB}\n")
        return Result(0, "")


class PhoneTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site(example_text(*ENTRY, *ON_CONTROL))
        self.out = []

    def phones(self, runner):
        return Phones(self.site, runner, out=self.out.append)

    def test_add_makes_the_key_here_and_writes_the_files(self):
        runner = Hosts()
        self.assertEqual(self.phones(runner).add("iphone", ask=lambda p: "yes"), 0, "\n".join(self.out))
        record = sitemod.read_phones(self.site.directory)["iphone"]
        self.assertEqual(record["address"], "10.255.254.2")
        folder = self.site.phones_dir / "iphone"
        private = (folder / "wg.key").read_text().strip()
        self.assertEqual(wgkey.public_key(private), record["public_key"])
        self.assertEqual(oct(folder.stat().st_mode & 0o777), "0o700")
        # Each entry got the phone's public key, never its private key.
        pushed = [c for c in runner.calls if "differs outside its peers" in c[2]]
        self.assertEqual([c[1] for c in pushed], ["cn-control", "ovs-control"])
        for call in pushed:
            self.assertIn(record["public_key"], call[2])
            self.assertNotIn(private, call[2])
        self.assertNotIn(private, "\n".join(self.out))
        cn = (folder / "cn.conf").read_text()
        self.assertIn(f"PrivateKey = {private}\nAddress = 10.255.254.2/32\nDNS = 10.255.254.1\nMTU = 1280", cn)
        self.assertIn("Endpoint = 198.51.100.10:51820\n"
                      "AllowedIPs = 100.64.1.0/24, 100.64.2.0/24, 10.255.2.0/24, 10.255.254.1/32", cn)
        clash = (folder / "clash.yaml").read_text()
        for line in ('  - name: "tn-cn"', '    server: "203.0.113.20"', "    port: 51821", f'    private-key: "{private}"',
                     "  - DOMAIN-SUFFIX,tailnet.internal,tailnet", "  - IP-CIDR,100.64.2.0/24,tailnet,no-resolve",
                     '  "web.ovs.tailnet.internal": "100.64.2.9"', '  "cn-control.tailnet.internal": "100.64.1.1"',
                     '    "+.tailnet.internal": "10.255.254.1#tailnet"', "  - IP-CIDR,10.255.254.1/32,tailnet,no-resolve"):
            self.assertIn(line, clash)
        # web is in both regions, so it has no short name.
        self.assertNotIn('"web.tailnet.internal"', clash)
        self.assertEqual(oct((folder / "clash.yaml").stat().st_mode & 0o777), "0o600")

    def test_add_again_keeps_the_key_and_address(self):
        self.phones(Hosts()).add("iphone", yes=True)
        first = sitemod.read_phones(self.site.directory)["iphone"]
        self.assertEqual(self.phones(Hosts()).add("iphone", yes=True), 0)
        self.assertEqual(sitemod.read_phones(self.site.directory)["iphone"], first)
        self.phones(Hosts()).add("ipad", yes=True)
        self.assertEqual(sitemod.read_phones(self.site.directory)["ipad"]["address"], "10.255.254.3")

    def test_needs_yes_and_a_good_name(self):
        runner = Hosts()
        self.assertEqual(self.phones(runner).add("iphone", ask=lambda p: "no"), 1)
        self.assertEqual(runner.calls, [])
        self.assertEqual(sitemod.read_phones(self.site.directory), {})
        with self.assertRaises(StepError):
            self.phones(runner).add("My Phone", yes=True)
        with self.assertRaises(StepError):
            Phones(self.load_site(name="plain"), runner).add("iphone", yes=True)

    def test_a_region_without_its_entry_yet(self):
        rc = self.phones(Hosts(absent={"ovs-control"})).add("iphone", yes=True)
        self.assertEqual(rc, 1)
        folder = self.site.phones_dir / "iphone"
        self.assertTrue((folder / "cn.conf").exists())
        self.assertFalse((folder / "ovs.conf").exists())
        self.assertIn("tn control apply ovs", "\n".join(self.out))
        self.assertIn("iphone", sitemod.read_phones(self.site.directory))  # control apply adds it there

    def test_remove(self):
        self.phones(Hosts()).add("iphone", yes=True)
        runner = Hosts()
        self.assertEqual(self.phones(runner).remove("iphone", yes=True), 0)
        self.assertEqual(sitemod.read_phones(self.site.directory), {})
        self.assertFalse((self.site.phones_dir / "iphone").exists())
        pushed = [c[2] for c in runner.calls if "differs outside its peers" in c[2]]
        self.assertEqual(len(pushed), 2)
        self.assertNotIn("10.255.254.2/32", pushed[0])
        with self.assertRaises(StepError):
            self.phones(runner).remove("iphone", yes=True)

    def test_stop_removes_only_the_entry(self):
        runner = Hosts()
        self.assertEqual(self.phones(runner).stop("ovs", ask=lambda p: "no"), 1)
        self.assertEqual(runner.calls, [])
        self.assertEqual(self.phones(runner).stop("ovs", yes=True), 0, "\n".join(self.out))
        sent = runner.scripts_for("ovs-control")
        self.assertEqual(len(sent), 2)
        self.assertIn('nft delete table inet "$ETABLE"', sent[0])
        self.assertNotIn(scripts.ROLLBACK_START.strip(), sent[0])
        self.assertIn("TN-LEFT", sent[1])
        self.assertEqual(runner.scripts_for("cn-control"), [])

    def test_status(self):
        sitemod.write_phones(self.site.directory, {"iphone": {"address": "10.255.254.2", "public_key": ENTRY_PUB}})
        self.site.phones = sitemod.read_phones(self.site.directory)

        class Entries(FakeRunner):
            def run(self, host, script, args=(), privileged=False, check=True, echo=True, secret=False):
                super().run(host, script, args, privileged, check, echo, secret)
                if host == "ovs-control":
                    return Result(0, "TN-FACT entry=absent\n")
                return Result(0, "TN-FACT wg=active\nTN-FACT dns=active\nTN-FACT keeper=active\nTN-FACT rules=ok\n"
                                 f"TN-FACT lookup=ok\nTN-BEGIN peers\n{ENTRY_PUB} 192.0.2.7:4500 75 6144 2048\n"
                                 f"{'X' * 43}= (none) -1 0 0\nTN-END peers\n")

        runner = Entries()
        self.assertEqual(self.phones(runner).status(), 1)  # ovs has no entry
        text = "\n".join(self.out)
        self.assertIn("✓ tunnel ✓ DNS ✓ lookup cn-control.cn.tailnet.internal ✓ accept rules", text)
        self.assertIn("iphone", text)
        self.assertIn("1 min ago", text)
        self.assertIn("6.0 kB / 2.0 kB", text)
        self.assertIn("unknown XXXXXXXX…", text)
        self.assertIn("never", text)
        self.assertIn("✗ no entry; tn control apply ovs", text)
        self.assertTrue(all(c[4] for c in runner.calls))  # as root, but nothing it runs changes anything

    def test_hosts_and_files_render_alone(self):
        hosts = phone_hosts(self.site, {"cn": json.loads(nodes_json(("db", "100.64.1.7"), ("bad", "192.0.2.9")))})
        self.assertEqual(hosts, [("db.cn.tailnet.internal", "100.64.1.7"), ("db.tailnet.internal", "100.64.1.7")])
        cn = self.site.regions["cn"]
        self.assertIn("[Peer]\nPublicKey = " + ENTRY_PUB, wg_conf(self.site, cn, "p", "K" * 43 + "=", "10.255.254.2", ENTRY_PUB))
        self.assertIn("hosts: {}", clash_yaml(self.site, "p", "K", "10.255.254.2", [(cn, ENTRY_PUB)], []))

    def test_cli_list(self):
        from tailscale_ops import cli
        sitemod.write_phones(self.site.directory, {"iphone": {"address": "10.255.254.2", "public_key": ENTRY_PUB}})
        rows = Phones(sitemod.load(self.site.directory, known_host=lambda a: True), None).rows()
        self.assertEqual(rows[1], ("iphone", "10.255.254.2", "none yet"))
        self.assertTrue(callable(cli.cmd_phone))


def dns_query(name, ident=b"\x12\x34"):
    return ident + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"".join(
        bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00\x00\x01\x00\x01"


def dns_answer(query, ip):
    q = entry_dns.question(query)
    return (query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + query[12:q[1]]
            + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(ip))


class EntryDNSTest(TempDirTest):
    def test_question_and_servfail(self):
        query = dns_query("Web.CN.Tailnet.Internal")
        name, end = entry_dns.question(query)
        self.assertEqual((name, end), ("web.cn.tailnet.internal", len(query)))
        for bad in (b"", query[:11], query[:-3], b"\x12\x34\x81\x80" + query[4:]):  # short, cut, a response
            self.assertIsNone(entry_dns.question(bad))
        fail = entry_dns.servfail(query, end)
        self.assertEqual((fail[:2], fail[2] & 0x80, fail[3] & 0x0F), (b"\x12\x34", 0x80, 2))
        self.assertEqual(fail[12:], query[12:])

    def test_tailnet_names_go_to_magicdns_and_the_rest_upstream(self):
        resolv = self.tmp / "resolv.conf"
        resolv.write_text("# test\nnameserver 192.0.2.53\nnameserver 10.255.254.1\n")
        asked = []
        real = entry_dns.ask_udp
        entry_dns.ask_udp = lambda server, query, port=53: asked.append(server) or dns_answer(query, "100.64.1.5")
        try:
            fwd = entry_dns.Forwarder("10.255.254.1", ["tailnet.internal"], "100.100.100.100", resolv_conf=str(resolv))
            fwd.answer(dns_query("web.cn.tailnet.internal"))
            fwd.answer(dns_query("tailnet.internal"))
            fwd.answer(dns_query("example.com"))
            fwd.answer(dns_query("eviltailnet.internal"))
        finally:
            entry_dns.ask_udp = real
        # The entry's own address in resolv.conf is skipped: it would ask itself.
        self.assertEqual(asked, ["100.100.100.100", "100.100.100.100", "192.0.2.53", "192.0.2.53"])

    def test_forwards_over_udp_and_tcp(self):
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.bind(("127.0.0.1", 0))
        port = upstream.getsockname()[1]
        upstream_tcp = socket.socket()
        upstream_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        upstream_tcp.bind(("127.0.0.1", port))
        upstream_tcp.listen()

        def serve_udp():
            data, peer = upstream.recvfrom(512)
            upstream.sendto(dns_answer(data, "100.64.1.7"), peer)

        def serve_tcp():
            conn, _ = upstream_tcp.accept()
            with conn:
                n = struct.unpack("!H", conn.recv(2))[0]
                answer = dns_answer(conn.recv(n), "100.64.1.8")
                conn.sendall(struct.pack("!H", len(answer)) + answer)

        threads = [threading.Thread(target=f, daemon=True) for f in (serve_udp, serve_tcp)]
        for th in threads:
            th.start()
        resolv = self.tmp / "resolv.conf"
        resolv.write_text("nameserver 127.0.0.1\n")
        fwd = entry_dns.Forwarder("10.255.254.1", ["tailnet.internal"], "127.0.0.1", resolv_conf=str(resolv),
                                  upstream_port=port)
        self.assertTrue(fwd.answer(dns_query("a.cn.tailnet.internal")).endswith(socket.inet_aton("100.64.1.7")))
        self.assertTrue(fwd.answer(dns_query("example.com"), tcp=True).endswith(socket.inet_aton("100.64.1.8")))
        upstream.close()
        upstream_tcp.close()
        # Nothing answers now: SERVFAIL, not silence.
        self.assertEqual(fwd.answer(dns_query("example.com"))[3] & 0x0F, 2)

    def test_installed_program_and_unit(self):
        site = self.load_site(example_text(*ENTRY))
        cn = site.regions["cn"]
        program = entry.dns_program(cn).splitlines()
        self.assertEqual(program[:2], ["#!/usr/bin/python3", "# tailnet-ops entry region=cn"])
        compile("\n".join(program), "tn-entry-dns", "exec")
        unit = entry.dns_unit(site, cn)
        self.assertTrue(unit.startswith("# tailnet-ops entry region=cn\n"))
        self.assertIn("ExecStart=/usr/local/sbin/tn-entry-dns --listen 10.255.254.1 --suffix tailnet.internal", unit)
        self.assertIn("DynamicUser=yes", unit)
        self.assertIn("BindsTo=wg-quick@tn-entry.service", unit)


class FirewallHookTest(TempDirTest):
    def test_input_chains(self):
        targets = firewall.blocking_targets(NFT_DROPS, "-P INPUT DROP\n", own_tables=("tn_entry",), hook="input")
        self.assertEqual([(t.label(), t.reason) for t in targets],
                         [("nft inet guard input", "drop rules"), ("iptables-legacy INPUT", "policy DROP")])
