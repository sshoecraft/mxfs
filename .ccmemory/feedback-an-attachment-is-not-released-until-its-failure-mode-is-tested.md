---
name: feedback-an-attachment-is-not-released-until-its-failure-mode-is-tested
description: USER 2026-10-04 (0.90.43): mpath boards passed on 2 healthy paths over one NIC; "not working unless tested fully". Failover and failback first.
metadata:
  type: feedback
---

**What happened.** For the `mpath` release I ran all eight `{2,4,8,16}/{net/mesh,disk/caw}/mpath` boards 31/31 with each node on a dm-multipath map over two iSCSI portals. Both portals were addresses on the same host bridge and each VM had one NIC; no row ever removed a path. I drafted the README as "released; path failover not verified".

**What the user said.** "Did you add two NICs to each VM and then disconnect one of the NICs to see if failover actually works? What about fail back?" and then: "I would not consider mpath to be working unless you've tested it fully ... people are going to be using this in production at some point, and if we say mpath is working and they test it and it's not, they're going to be pissed."

**The rule (my wording of it).** A release claim for a feature whose whole purpose is surviving a failure (multipath, replication, redundancy, fencing) is not earned by the happy path. Before the claim: build the real topology (independent NICs/networks per path, not aliases on one wire), inject the failure under load, and verify recovery in both directions (failover AND failback, and I/O actually carried by the returned path). Writing the gap into the README as "not verified" is not an acceptable substitute for testing it when the claim is "released".

**How to apply.** When a ccloop criterion says "boards pass on X", ask what a production user would do to X on day one and make that a suite row on X's columns before releasing. Scope: any attachment or redundancy feature, not only mpath.
