"""The names keeper on each control host: its records match tn's, and two keepers swap lists."""

import json
import os
import subprocess

from tailscale_ops import names, scripts
from tailscale_ops.remote import Result
from tests.helpers import FakeRunner, TempDirTest, bash


def node(i, name, ip, hostname=None):
    """A node as `headscale nodes list -o json` prints it, nested objects and all."""
    return {"id": i, "machine_key": "mkey:0", "ip_addresses": [ip, f"fd7a:115c:a1e0::{i}"],
            "name": hostname or name, "user": {"id": 1, "name": "owner", "created_at": {"seconds": 1}},
            "pre_auth_key": {"id": i, "key": "hskey-auth-x-***", "acl_tags": ["tag:cn-server"]},
            "given_name": name, "online": True, "tags": []}


NODES = {
    "cn": [node(1, "cn-control", "100.64.1.1"), node(2, "cn-gateway", "100.64.1.2"),
           node(3, "Shared", "100.64.1.9", hostname='odd "{host}" [name]'),
           node(4, "v6-only", "fd7a:115c:a1e0::44")],
    "ovs": [node(1, "ovs-control", "100.64.2.1"), node(2, "ovs-line", "100.64.2.4"), node(3, "shared", "100.64.2.9"),
            node(4, "stray", "100.64.1.77")],       # an address outside ovs's range is ignored
}


class KeeperRun(TempDirTest):
    """Both control hosts' keepers in temp directories; `ssh` from cn runs ovs's keeper exchange."""

    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.dirs = {}
        for name, nodes in NODES.items():
            d = self.tmp / name
            (d / "names" / "peers").mkdir(parents=True)
            (d / "state").mkdir()
            (d / "nodes.json").write_text(json.dumps(nodes, indent="\t"))
            fake = d / "headscale"
            fake.write_text(f"#!/bin/bash\ncat {d / 'nodes.json'}\n")
            fake.chmod(0o755)
            keeper = d / "names" / "keeper"
            keeper.write_text(names.keeper_script(self.site, self.site.regions[name], bin_path=str(fake),
                                                  keeper_dir=str(d / "names"), state=str(d / "state"),
                                                  records_file=str(d / "extra-records.json"),
                                                  owner=f"{os.getuid()}:{os.getgid()}"))
            keeper.chmod(0o755)
            self.dirs[name] = d
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        ssh = bin_dir / "ssh"
        ssh.write_text(f"#!/bin/bash\nexec {self.dirs['ovs'] / 'names' / 'keeper'} exchange cn\n")
        ssh.chmod(0o755)
        self.env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
        cn, ovs = self.site.regions["cn"], self.site.regions["ovs"]
        self.conf("cn", "ovs", f"prefix={ovs.ipv4_prefix}\nalias={ovs.alias_net}\ntarget=root@203.0.113.20\nport=22\n")
        self.conf("ovs", "cn", f"prefix={cn.ipv4_prefix}\nalias={cn.alias_net}\n")

    def conf(self, region, peer, text):
        (self.dirs[region] / "names" / "peers" / f"{peer}.conf").write_text(text)

    def keeper(self, region, *args, stdin=""):
        return subprocess.run([bash(), str(self.dirs[region] / "names" / "keeper"), *args], input=stdin,
                              capture_output=True, text=True, env=self.env)

    def records(self, region):
        return (self.dirs[region] / "extra-records.json").read_text()

    def expected(self, region):
        nodes = {name: [{**n, "given_name": n["given_name"].lower()} for n in ns] for name, ns in NODES.items()}
        recs, _ = names.records(self.site, self.site.regions[region], nodes)
        return json.dumps(recs, indent=2) + "\n"

    def test_reads_the_nodes(self):
        p = self.keeper("cn", "local")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual((self.dirs["cn"] / "state" / "cn.tsv").read_text(),
                         "cn-control 100.64.1.1\ncn-gateway 100.64.1.2\nshared 100.64.1.9\n")

    def test_one_call_gives_both_sides_the_same_records_as_tn(self):
        p = self.keeper("cn", "run")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("names: wrote", p.stderr)
        self.assertEqual(self.records("cn"), self.expected("cn"))
        self.assertEqual(self.records("ovs"), self.expected("ovs"))     # the exchange wrote ovs's side too
        self.assertEqual(oct((self.dirs["cn"] / "extra-records.json").stat().st_mode & 0o777), "0o640")
        again = self.keeper("cn", "run")
        self.assertEqual((again.returncode, again.stderr), (0, ""))     # nothing changed, nothing written

    def test_a_refused_list_changes_nothing(self):
        self.keeper("cn", "run")
        before = self.records("ovs")
        for bad in ("evil 198.51.100.7\n", "Bad_Name 100.64.1.5\n", "a b c\n", "x 100.64.1.300\n"):
            p = self.keeper("ovs", "exchange", "cn", stdin=bad)
            self.assertEqual(p.returncode, 1, bad)
            self.assertIn("refused the list from cn", p.stderr)
            self.assertEqual(p.stdout, "")
        self.assertEqual(self.records("ovs"), before)
        self.assertIn("is not a peer", self.keeper("ovs", "exchange", "nowhere", stdin="").stderr)
        self.assertIn("needs a region name", self.keeper("ovs", "exchange", "../x", stdin="").stderr)

    def test_a_failed_call_keeps_the_last_list(self):
        self.keeper("cn", "run")
        (self.tmp / "bin" / "ssh").write_text("#!/bin/bash\necho 'ssh: connect to host: Connection refused' >&2\nexit 255\n")
        p = self.keeper("cn", "run")
        self.assertEqual(p.returncode, 1)
        self.assertIn("could not swap names with ovs (root@203.0.113.20): ssh: connect to host: Connection refused",
                      p.stderr)
        self.assertEqual(self.records("cn"), self.expected("cn"))
        (self.tmp / "bin" / "ssh").write_text("#!/bin/bash\necho 'Welcome!'\n")
        self.assertIn("answered with something other than its list: Welcome!", self.keeper("cn", "run").stderr)

    def test_no_headscale_no_change(self):
        self.keeper("cn", "local")
        before = self.records("cn")
        (self.dirs["cn"] / "headscale").write_text("#!/bin/bash\nexit 1\n")
        p = self.keeper("cn", "local")
        self.assertEqual(p.returncode, 1)
        self.assertIn("headscale nodes list failed", p.stderr)
        self.assertEqual(self.records("cn"), before)

    def test_no_peers(self):
        for d in self.dirs.values():
            for f in (d / "names" / "peers").iterdir():
                f.unlink()
        self.keeper("cn", "run")
        self.assertEqual(json.loads(self.records("cn")),
                         [{"name": f"{n}.cn.tailnet.internal", "type": "A", "value": ip} for n, ip in
                          (("cn-control", "100.64.1.1"), ("cn-gateway", "100.64.1.2"), ("shared", "100.64.1.9"))])


class SyncTest(TempDirTest):
    """Names.sync hands each keeper its peers, their lists and the keys; the line's initiator side calls."""

    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.views = {"cn-control": {"user": "root", "hostname": "198.51.100.10", "port": "22"},
                      "ovs-control": {"user": "admin", "hostname": "203.0.113.20", "port": "2222"}}

    def runner(self, keepers=("cn", "ovs"), akf="yes"):
        def peek(region):
            text = json.dumps(NODES[region])
            if region in keepers:
                text += (f"\nTN-FACT names_keeper=yes\nTN-FACT names_key=ssh-ed25519 AAAA{region} tailnet-ops names "
                         f"{region}\nTN-FACT names_akf={akf}\n")
            return text + f"TN-BEGIN hostkeys\nssh-ed25519 HOST{region}\nTN-END hostkeys\n"

        class R(FakeRunner):
            def run(self, host, script, args=(), privileged=False, check=True, echo=True, secret=False):
                self.calls.append(("run", host, script, tuple(args), privileged))
                if names.PEEK in script:
                    return Result(0, peek(host.split("-")[0]))
                return Result(0, "")
        return R()

    def sync(self, runner, **kw):
        out = []
        names.Names(self.site, runner, out=out.append, ssh_view=lambda h: self.views[h]).sync(**kw)
        return out

    def body(self, runner, host):
        return [c[2] for c in runner.calls if c[1] == host and "names_put" in c[2]][0]

    def test_pairs_the_keepers(self):
        runner = self.runner()
        out = self.sync(runner)
        cn, ovs = self.body(runner, "cn-control"), self.body(runner, "ovs-control")
        # cn holds the line's initiator, so cn calls ovs, as the user and port the operator's SSH uses
        self.assertIn("target=admin@203.0.113.20\nport=2222\n", cn)
        self.assertIn("[203.0.113.20]:2222 ssh-ed25519 HOSTovs\n", cn)
        self.assertNotIn("target=", ovs)
        self.assertIn('restrict,command="sudo -n /etc/headscale/names/keeper exchange cn" ssh-ed25519 AAAAcn '
                      "tailnet-ops-names site=example peer=cn\n", ovs)
        self.assertIn("names_authorize admin <<'TN_EOF'\nrestrict", ovs)
        self.assertIn("names_authorize root <<'TN_EOF'\nTN_EOF", cn)          # nobody calls cn
        self.assertIn("ovs-control 100.64.2.1\novs-line 100.64.2.4\nshared 100.64.2.9\nTN_EOF", cn)   # fresh list
        self.assertNotIn("stray", cn)
        self.assertTrue(any("✓ cn-control swaps names with ovs-control" in line for line in out))
        for body in (cn, ovs):
            script = scripts.wrap(scripts.control_prelude(self.site, self.site.regions["cn"]), body)
            p = subprocess.run([bash(), "-n"], input=script, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)

    def test_without_a_keeper_the_records_are_written(self):
        runner = self.runner(keepers=("cn",))
        self.sync(runner)
        self.assertNotIn("target=", self.body(runner, "cn-control"))             # ovs cannot answer a call
        self.assertTrue(any("extra-records.json.tn-new" in c[2] for c in runner.calls if c[1] == "ovs-control"))

    def test_a_jump_host_or_another_authorized_keys_file_means_no_calls(self):
        self.views["ovs-control"]["proxyjump"] = "bastion"
        runner = self.runner()
        self.sync(runner)
        self.assertNotIn("target=", self.body(runner, "cn-control"))
        self.views["ovs-control"].pop("proxyjump")
        runner = self.runner(akf="no")
        out = self.sync(runner)
        self.assertNotIn("target=", self.body(runner, "cn-control"))
        self.assertTrue(any("does not read ~/.ssh/authorized_keys" in line for line in out))

    def test_a_rolled_back_line_or_region_unpairs(self):
        runner = self.runner()
        self.sync(runner, skip_lines=("line1",))
        cn, ovs = self.body(runner, "cn-control"), self.body(runner, "ovs-control")
        self.assertIn("PEERS=''", cn)
        self.assertIn("names_authorize admin <<'TN_EOF'\nTN_EOF", ovs)          # cn's key is taken away
        runner = self.runner()
        self.sync(runner, tolerant=True, gone=("cn",))
        self.assertEqual({c[1] for c in runner.calls}, {"ovs-control"})
        self.assertIn("PEERS=''", self.body(runner, "ovs-control"))

    def test_tolerant_skips_a_silent_host(self):
        runner = self.runner()
        real = runner.run

        def run(host, script, **kw):
            if host == "ovs-control":
                return Result(255, "")
            return real(host, script, **kw)
        runner.run = run
        out = self.sync(runner, tolerant=True)
        self.assertIn("    ovs-control (ovs): no answer; left as it is", out)
        self.assertIn("    cn-control (cn): left as it is until ovs-control answers; then run `tn dns sync`", out)
        self.assertEqual([c for c in runner.calls if c[1] == "cn-control" and names.PEEK not in c[2]], [])

    def test_a_region_without_headscale_yet_is_left_out(self):
        runner = self.runner()
        real = runner.run

        def run(host, script, **kw):
            if host == "ovs-control" and names.PEEK in script:
                return Result(0, "TN-FACT headscale=absent\n")
            return real(host, script, **kw)
        runner.run = run
        out = self.sync(runner, tolerant=True)
        self.assertIn("    ovs-control (ovs): no Headscale yet", out)
        self.assertIn("PEERS=''", self.body(runner, "cn-control"))

    def test_a_node_named_like_a_fact(self):
        runner = self.runner()
        real = runner.run

        def run(host, script, **kw):
            if host == "ovs-control" and names.PEEK in script:
                return Result(0, json.dumps([node(1, "tn-box", "100.64.2.7", hostname="TN-box")], indent="\t")
                              + "\nTN-FACT names_keeper=yes\n")
            return real(host, script, **kw)
        runner.run = run
        self.sync(runner)
        self.assertIn("tn-box 100.64.2.7\n", self.body(runner, "cn-control"))


class ScriptsTest(TempDirTest):
    def test_install_and_uninstall_are_valid_bash(self):
        site = self.load_site()
        region = site.regions["cn"]
        for body in (names.install(site, region), names.uninstall(site, "admin")):
            script = scripts.wrap(scripts.control_prelude(site, region), body)
            p = subprocess.run([bash(), "-n"], input=script, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(names.keeper_script(site, region).rstrip(), names.install(site, region))
        self.assertIn("names_authorize admin </dev/null", names.uninstall(site, "admin"))

    def test_authorize_keeps_every_other_key(self):
        home = self.tmp / "home"
        (home / ".ssh").mkdir(parents=True)
        keys = home / ".ssh" / "authorized_keys"
        keys.write_text("ssh-ed25519 OPERATOR me@laptop\nold tailnet-ops-names site=example peer=cn\n")
        keys.chmod(0o600)
        user = subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()
        script = (f'die() {{ echo "$*" >&2; exit 1; }}\ngetent() {{ echo "{user}:x:1:1::{home}:/bin/sh"; }}\n'
                  f"chmod() {{ command chmod \"${{@/--reference=*/600}}\"; }}\nchown() {{ :; }}\n"
                  f"NAMES_TAG='tailnet-ops-names site=example'\n{names.AUTHORIZE}"
                  f"names_authorize {user} <<'X'\nrestrict,command=\"k exchange cn\" ssh-ed25519 NEW "
                  "tailnet-ops-names site=example peer=cn\nX\n")
        p = subprocess.run([bash(), "-s"], input=script, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(keys.read_text(), 'ssh-ed25519 OPERATOR me@laptop\nrestrict,command="k exchange cn" '
                                           "ssh-ed25519 NEW tailnet-ops-names site=example peer=cn\n")
        p = subprocess.run([bash(), "-s"], input=script.split("names_authorize " + user)[0]
                           + f"names_authorize {user} </dev/null\n", capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(keys.read_text(), "ssh-ed25519 OPERATOR me@laptop\n")
