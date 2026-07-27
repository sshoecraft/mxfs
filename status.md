```text



=== MXFS TEST STATUS — conditions — nodes=1 dlm=tcp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 1/tcp   | ✅ PASS    | 0/300s    | skipped (marker matched 1/tcp)
2   | suite    | precond_readiness        | 1/tcp   | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | posix_single             | 1/tcp   | ✅ PASS    | 2/15s     | checks=29 passed=29 failed=0
4   | suite    | fsx                      | 1/tcp   | ✅ PASS    | 50/88s    | checks=2 passed=2 failed=0
5   | suite    | fio_verify               | 1/tcp   | ✅ PASS    | 23/42s    | checks=3 passed=3 failed=0
6   | suite    | integrity_filetypes      | 1/tcp   | ✅ PASS    | 2/10s     | checks=13 passed=13 failed=0
7   | suite    | fio_perf                 | 1/tcp   | ✅ PASS    | 72/120s   | nodes_pass=1/1 seqW=276MiB/s seqR=10240MiB/s randW=961iops randR=107436iops
8   | suite    | fio_perf_vs_xfs          | 1/tcp   | ✅ PASS    | 1/10s     | seqW=103% seqR=680% randW=93% randR=585% worst(write)=93% (threshold>=70%, wsrc=raw-ceiling)
9   | suite    | cache_coherency          | 1/tcp   | ✅ PASS    | 1/60s     | nodes_pass=1/1 checks=530 passed=530 failed=0
10  | suite    | strong_consistency       | 1/tcp   | ✅ PASS    | 1/30s     | nodes_pass=1/1 checks=7 passed=7 failed=0
11  | suite    | posix_multi              | 1/tcp   | ✅ PASS    | 1/30s     | nodes_pass=1/1 checks=266 passed=266 failed=0
12  | suite    | mmap_coherency           | 1/tcp   | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=4 passed=4 failed=0
13  | suite    | zero_silent_loss         | 1/tcp   | ✅ PASS    | 0/60s     | nodes_pass=1/1 checks=24 passed=24 failed=0
14  | suite    | dlm_fairness             | 1/tcp   | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=5 passed=5 failed=0
15  | suite    | scaling_curve            | 1/tcp   | ✅ PASS    | 2/90s     | nodes_pass=1/1 checks=7 passed=7 failed=0
16  | suite    | dlm_scaling              | 1/tcp   | ✅ PASS    | 7/90s     | nodes_pass=1/1 checks=6 passed=6 failed=0
17  | suite    | rsync_paired             | 1/tcp   | ✅ PASS    | 3/60s     | nodes_pass=1/1 checks=6 passed=6 failed=0
18  | suite    | fault_enospc             | 1/tcp   | ✅ PASS    | 1/10s     | checks=4 passed=4 failed=0
19  | suite    | crash_consistency        | 1/tcp   | ✅ PASS    | 3/90s     | nodes_pass=1/1 checks=54 passed=54 failed=0
20  | suite    | dir_reuse_coherency      | 1/tcp   | ✅ PASS    | 50/120s   | nodes_pass=1/1 checks=170 passed=170 failed=0
21  | suite    | soak                     | 1/tcp   | ✅ PASS    | 31/60s    | dur=30s ops=1893 errs=0 dmesg_hits=0
22  | tooling  | mkfs_timing              | 1/tcp   | ✅ PASS    | 2/10s     | 1041ms (threshold<=10000ms)
23  | tooling  | chk_clean                | 1/tcp   | ✅ PASS    | 0/10s     | rc=0 errors=0
24  | tooling  | online_resize            | 1/tcp   | ✅ PASS    | 3/25s     | pre=1695MB post=3743MB delta=2048MB/+2048MB data_intact=yes
25  | tooling  | dkms_install             | 1/tcp   | ✅ PASS    | 111/240s  | add=0 build=0 install=0 installed=yes remove=0 clean=yes
26  | tooling  | single_node_paired       | 1/tcp   | ✅ PASS    | 59/90s    | xfs=(5518/3867/5114/3951)ms mxfs=(3533/3202/4216/5918)ms round_ratios=64,82,82,149 ratio=82% files=8714/8714
27  | tooling  | fio_vs_xfs_baseline      | 1/tcp   | ✅ PASS    | 134/180s  | seqW=149/508MiB rounds=30,29,418,128→79% randW=1011/596iops rounds=61,169,101,111→106% worst_write=79% [reads cache-bound: seqR 102% randR 97%]
28  | tooling  | cluster_ops_timing       | 1/tcp   | ✅ PASS    | 2/10s     | first=51ms rest=52ms umount=471ms
29  | tooling  | fault_io_error           | 1/tcp   | ✅ PASS    | 9/60s     | nodes_pass=1/1 eio=yes wms=5 bad_dmesg=0 remount=yes data_intact=yes chk_rc=0
------------------------------------------------------------------------------------------
Total: 29 — 29 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=1 dlm=tcp]

=== MXFS TEST STATUS — conditions — nodes=2 dlm=tcp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 2/tcp   | ✅ PASS    | 0/300s    | skipped (marker matched 2/tcp)
2   | suite    | precond_readiness        | 2/tcp   | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 2/tcp   | ✅ PASS    | 97/120s   | nodes_pass=2/2 seqW=1179MiB/s seqR=20029MiB/s randW=884iops randR=190512iops
4   | suite    | fio_perf_vs_xfs          | 2/tcp   | ✅ PASS    | 1/10s     | seqW=658% seqR=1330% randW=85% randR=1038% worst(write)=85% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 2/tcp   | ✅ PASS    | 6/60s     | nodes_pass=2/2 checks=534 passed=534 failed=0
6   | suite    | strong_consistency       | 2/tcp   | ✅ PASS    | 1/30s     | nodes_pass=2/2 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 2/tcp   | ✅ PASS    | 1/30s     | nodes_pass=2/2 checks=140 passed=140 failed=0
8   | suite    | mmap_coherency           | 2/tcp   | ✅ PASS    | 1/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
9   | suite    | zero_silent_loss         | 2/tcp   | ✅ PASS    | 1/60s     | nodes_pass=2/2 checks=44 passed=44 failed=0
10  | suite    | dlm_fairness             | 2/tcp   | ✅ PASS    | 2/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 2/tcp   | ✅ PASS    | 5/30s     | nodes_pass=2/2 checks=6 passed=6 failed=0
12  | suite    | scaling_curve            | 2/tcp   | ✅ PASS    | 2/90s     | nodes_pass=2/2 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 2/tcp   | ✅ PASS    | 1/90s     | nodes_pass=2/2 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 2/tcp   | ✅ PASS    | 4/60s     | nodes_pass=2/2 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 2/tcp   | ✅ PASS    | 5/90s     | nodes_pass=2/2 checks=104 passed=104 failed=0
16  | suite    | dir_reuse_coherency      | 2/tcp   | ✅ PASS    | 88/120s   | nodes_pass=2/2 checks=170 passed=170 failed=0
17  | suite    | fence_during_write       | 2/tcp   | ✅ PASS    | 16/60s    | nodes_pass=2/2 checks=8 passed=8 failed=0
18  | suite    | fault_netpartition       | 2/tcp   | ✅ PASS    | 8/60s     | nodes_pass=2/2 checks=5 passed=5 failed=0
19  | suite    | soak                     | 2/tcp   | ✅ PASS    | 31/60s    | dur=30s ops=1713 errs=0 dmesg_hits=0
20  | tcp      | tcp_dlm_scaling          | 2/tcp   | ✅ PASS    | 18/300s   | nodes_pass=2/2 checks=7 passed=7 failed=0
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=2 dlm=tcp]

=== MXFS TEST STATUS — conditions — nodes=4 dlm=tcp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 4/tcp   | ✅ PASS    | 23/300s   | elapsed=23s (fresh prep)
2   | suite    | precond_readiness        | 4/tcp   | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 4/tcp   | ✅ PASS    | 86/120s   | nodes_pass=4/4 seqW=663MiB/s seqR=30616MiB/s randW=1105iops randR=345330iops
4   | suite    | fio_perf_vs_xfs          | 4/tcp   | ✅ PASS    | 0/10s     | seqW=394% seqR=2034% randW=107% randR=1883% worst(write)=107% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 4/tcp   | ✅ PASS    | 7/60s     | nodes_pass=4/4 checks=542 passed=542 failed=0
6   | suite    | strong_consistency       | 4/tcp   | ✅ PASS    | 2/30s     | nodes_pass=4/4 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 4/tcp   | ✅ PASS    | 2/30s     | nodes_pass=4/4 checks=80 passed=80 failed=0
8   | suite    | mmap_coherency           | 4/tcp   | ✅ PASS    | 0/30s     | nodes_pass=4/4 checks=7 passed=7 failed=0
9   | suite    | zero_silent_loss         | 4/tcp   | ✅ PASS    | 2/60s     | nodes_pass=4/4 checks=84 passed=84 failed=0
10  | suite    | dlm_fairness             | 4/tcp   | ✅ PASS    | 4/30s     | nodes_pass=4/4 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 4/tcp   | ✅ PASS    | 3/30s     | nodes_pass=4/4 checks=6 passed=6 failed=0
12  | suite    | scaling_curve            | 4/tcp   | ✅ PASS    | 2/90s     | nodes_pass=4/4 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 4/tcp   | ✅ PASS    | 9/90s     | nodes_pass=4/4 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 4/tcp   | ✅ PASS    | 3/60s     | nodes_pass=4/4 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 4/tcp   | ✅ PASS    | 10/90s    | nodes_pass=4/4 checks=204 passed=204 failed=0
16  | suite    | dir_reuse_coherency      | 4/tcp   | ✅ PASS    | 104/120s  | nodes_pass=4/4 checks=170 passed=170 failed=0
17  | suite    | fence_during_write       | 4/tcp   | ✅ PASS    | 17/60s    | nodes_pass=4/4 checks=8 passed=8 failed=0
18  | suite    | fault_netpartition       | 4/tcp   | ✅ PASS    | 7/60s     | nodes_pass=4/4 checks=5 passed=5 failed=0
19  | suite    | soak                     | 4/tcp   | ✅ PASS    | 32/60s    | dur=30s ops=1780 errs=0 dmesg_hits=0
20  | tcp      | tcp_dlm_scaling          | 4/tcp   | ✅ PASS    | 17/300s   | nodes_pass=4/4 checks=7 passed=7 failed=0
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=4 dlm=tcp]

=== MXFS TEST STATUS — conditions — nodes=8 dlm=tcp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 8/tcp   | ✅ PASS    | 0/300s    | skipped (marker matched 8/tcp)
2   | suite    | precond_readiness        | 8/tcp   | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 8/tcp   | ✅ PASS    | 94/120s   | nodes_pass=8/8 seqW=594MiB/s seqR=45471MiB/s randW=1103iops randR=654695iops
4   | suite    | fio_perf_vs_xfs          | 8/tcp   | ✅ PASS    | 0/10s     | seqW=286% seqR=3021% randW=115% randR=3570% worst(write)=115% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 8/tcp   | ✅ PASS    | 10/60s    | nodes_pass=8/8 checks=558 passed=558 failed=0
6   | suite    | strong_consistency       | 8/tcp   | ✅ PASS    | 2/30s     | nodes_pass=8/8 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 8/tcp   | ✅ PASS    | 2/30s     | nodes_pass=8/8 checks=56 passed=56 failed=0
8   | suite    | mmap_coherency           | 8/tcp   | ✅ PASS    | 1/30s     | nodes_pass=8/8 checks=11 passed=11 failed=0
9   | suite    | zero_silent_loss         | 8/tcp   | ✅ PASS    | 3/60s     | nodes_pass=8/8 checks=164 passed=164 failed=0
10  | suite    | dlm_fairness             | 8/tcp   | ✅ PASS    | 7/30s     | nodes_pass=8/8 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 8/tcp   | ✅ PASS    | 4/30s     | nodes_pass=8/8 checks=6 passed=6 failed=0
12  | suite    | scaling_curve            | 8/tcp   | ✅ PASS    | 4/90s     | nodes_pass=8/8 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 8/tcp   | ✅ PASS    | 13/90s    | nodes_pass=8/8 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 8/tcp   | ✅ PASS    | 6/60s     | nodes_pass=8/8 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 8/tcp   | ✅ PASS    | 19/90s    | nodes_pass=8/8 checks=404 passed=404 failed=0
16  | suite    | dir_reuse_coherency      | 8/tcp   | ✅ PASS    | 102/120s  | nodes_pass=8/8 checks=142 passed=142 failed=0
17  | suite    | fence_during_write       | 8/tcp   | ✅ PASS    | 21/60s    | nodes_pass=8/8 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 8/tcp   | ✅ PASS    | 8/60s     | nodes_pass=8/8 checks=5 passed=5 failed=0
19  | suite    | soak                     | 8/tcp   | ✅ PASS    | 32/60s    | dur=30s ops=1650 errs=0 dmesg_hits=0
20  | tcp      | tcp_dlm_scaling          | 8/tcp   | ✅ PASS    | 27/300s   | nodes_pass=8/8 checks=7 passed=7 failed=0
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=8 dlm=tcp]

=== MXFS TEST STATUS — conditions — nodes=16 dlm=tcp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 16/tcp  | ✅ PASS    | 0/300s    | skipped (marker matched 16/tcp)
2   | suite    | precond_readiness        | 16/tcp  | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 16/tcp  | ✅ PASS    | 115/120s  | nodes_pass=16/16 seqW=1090MiB/s seqR=40533MiB/s randW=792iops randR=882333iops
4   | suite    | fio_perf_vs_xfs          | 16/tcp  | ✅ PASS    | 1/10s     | seqW=250% seqR=2693% randW=76% randR=4811% worst(write)=76% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 16/tcp  | ✅ PASS    | 13/60s    | nodes_pass=16/16 checks=590 passed=590 failed=0
6   | suite    | strong_consistency       | 16/tcp  | ✅ PASS    | 3/30s     | nodes_pass=16/16 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 16/tcp  | ✅ PASS    | 4/30s     | nodes_pass=16/16 checks=56 passed=56 failed=0
8   | suite    | mmap_coherency           | 16/tcp  | ✅ PASS    | 3/30s     | nodes_pass=16/16 checks=19 passed=19 failed=0
9   | suite    | zero_silent_loss         | 16/tcp  | ✅ PASS    | 7/60s     | nodes_pass=16/16 checks=324 passed=324 failed=0
10  | suite    | dlm_fairness             | 16/tcp  | ✅ PASS    | 11/30s    | nodes_pass=16/16 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 16/tcp  | ✅ PASS    | 4/30s     | nodes_pass=16/16 checks=6 passed=6 failed=0
12  | suite    | scaling_curve            | 16/tcp  | ✅ PASS    | 9/90s     | nodes_pass=16/16 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 16/tcp  | ✅ PASS    | 16/90s    | nodes_pass=16/16 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 16/tcp  | ✅ PASS    | 16/60s    | nodes_pass=16/16 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 16/tcp  | ✅ PASS    | 39/90s    | nodes_pass=16/16 checks=354 passed=354 failed=0
16  | suite    | dir_reuse_coherency      | 16/tcp  | ✅ PASS    | 105/120s  | nodes_pass=16/16 checks=114 passed=114 failed=0
17  | suite    | fence_during_write       | 16/tcp  | ✅ PASS    | 22/60s    | nodes_pass=16/16 checks=8 passed=8 failed=0
18  | suite    | fault_netpartition       | 16/tcp  | ✅ PASS    | 8/60s     | nodes_pass=16/16 checks=5 passed=5 failed=0
19  | suite    | soak                     | 16/tcp  | ✅ PASS    | 31/60s    | dur=30s ops=1733 errs=0 dmesg_hits=0
20  | tcp      | tcp_dlm_scaling          | 16/tcp  | ✅ PASS    | 25/300s   | nodes_pass=16/16 checks=7 passed=7 failed=0
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=16 dlm=tcp]

=== MXFS TEST STATUS — conditions — nodes=32 dlm=tcp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 32/tcp  | ✅ PASS    | 0/300s    | skipped (marker matched 32/tcp)
2   | suite    | precond_readiness        | 32/tcp  | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 32/tcp  | ✅ PASS    | 92/120s   | nodes_pass=32/32 seqW=4376MiB/s seqR=43460MiB/s randW=1177iops randR=842747iops
4   | suite    | fio_perf_vs_xfs          | 32/tcp  | ✅ PASS    | 0/10s     | seqW=804% seqR=2887% randW=100% randR=4595% worst(write)=100% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 32/tcp  | ✅ PASS    | 23/60s    | nodes_pass=32/32 checks=654 passed=654 failed=0
6   | suite    | strong_consistency       | 32/tcp  | ✅ PASS    | 6/30s     | nodes_pass=32/32 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 32/tcp  | ✅ PASS    | 7/30s     | nodes_pass=32/32 checks=80 passed=80 failed=0
8   | suite    | mmap_coherency           | 32/tcp  | ✅ PASS    | 4/30s     | nodes_pass=32/32 checks=35 passed=35 failed=0
9   | suite    | zero_silent_loss         | 32/tcp  | ✅ PASS    | 20/60s    | nodes_pass=32/32 checks=644 passed=644 failed=0
10  | suite    | dlm_fairness             | 32/tcp  | ✅ PASS    | 11/30s    | nodes_pass=32/32 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 32/tcp  | ✅ PASS    | 5/30s     | nodes_pass=32/32 checks=6 passed=6 failed=0
12  | suite    | scaling_curve            | 32/tcp  | ✅ PASS    | 38/90s    | nodes_pass=32/32 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 32/tcp  | ✅ PASS    | 33/90s    | nodes_pass=32/32 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 32/tcp  | ✅ PASS    | 39/60s    | nodes_pass=32/32 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 32/tcp  | ✅ PASS    | 36/90s    | nodes_pass=32/32 checks=204 passed=204 failed=0
16  | suite    | dir_reuse_coherency      | 32/tcp  | ✅ PASS    | 113/120s  | nodes_pass=32/32 checks=72 passed=72 failed=0
17  | suite    | fence_during_write       | 32/tcp  | ✅ PASS    | 31/60s    | nodes_pass=32/32 checks=8 passed=8 failed=0
18  | suite    | fault_netpartition       | 32/tcp  | ✅ PASS    | 10/60s    | nodes_pass=32/32 checks=5 passed=5 failed=0
19  | suite    | soak                     | 32/tcp  | ✅ PASS    | 31/60s    | dur=30s ops=692 errs=0 dmesg_hits=0
20  | tcp      | tcp_dlm_scaling          | 32/tcp  | ✅ PASS    | 48/300s   | nodes_pass=32/32 checks=7 passed=7 failed=0
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=32 dlm=tcp]



=== MXFS TEST STATUS — conditions — nodes=1 dlm=cawp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 1/cawp  | ✅ PASS    | 0/300s    | skipped (marker matched 1/cawp)
2   | suite    | precond_readiness        | 1/cawp  | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | posix_single             | 1/cawp  | ✅ PASS    | 1/15s     | checks=29 passed=29 failed=0
4   | suite    | fsx                      | 1/cawp  | ✅ PASS    | 10/88s    | checks=2 passed=2 failed=0
5   | suite    | fio_verify               | 1/cawp  | ✅ PASS    | 3/42s     | checks=3 passed=3 failed=0
6   | suite    | integrity_filetypes      | 1/cawp  | ✅ PASS    | 2/10s     | checks=13 passed=13 failed=0
7   | suite    | fio_perf                 | 1/cawp  | ✅ PASS    | 12/120s   | nodes_pass=1/1 seqW=1976MiB/s seqR=1715MiB/s randW=38963iops randR=42834iops
8   | suite    | fio_perf_vs_xfs          | 1/cawp  | ✅ PASS    | 0/10s     | seqW=113% seqR=92% randW=88% randR=100% worst(write)=88% (threshold>=70%, wsrc=xfs-baseline)
9   | suite    | cache_coherency          | 1/cawp  | ✅ PASS    | 1/60s     | nodes_pass=1/1 checks=530 passed=530 failed=0
10  | suite    | strong_consistency       | 1/cawp  | ✅ PASS    | 1/30s     | nodes_pass=1/1 checks=7 passed=7 failed=0
11  | suite    | posix_multi              | 1/cawp  | ✅ PASS    | 1/30s     | nodes_pass=1/1 checks=266 passed=266 failed=0
12  | suite    | mmap_coherency           | 1/cawp  | ✅ PASS    | 1/30s     | nodes_pass=1/1 checks=4 passed=4 failed=0
13  | suite    | zero_silent_loss         | 1/cawp  | ✅ PASS    | 1/60s     | nodes_pass=1/1 checks=24 passed=24 failed=0
14  | suite    | dlm_fairness             | 1/cawp  | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=5 passed=5 failed=0
15  | suite    | scaling_curve            | 1/cawp  | ✅ PASS    | 1/90s     | nodes_pass=1/1 checks=7 passed=7 failed=0
16  | suite    | dlm_scaling              | 1/cawp  | ✅ PASS    | 9/90s     | nodes_pass=1/1 checks=6 passed=6 failed=0
17  | suite    | rsync_paired             | 1/cawp  | ✅ PASS    | 3/60s     | nodes_pass=1/1 checks=6 passed=6 failed=0
18  | suite    | fault_enospc             | 1/cawp  | ✅ PASS    | 1/10s     | checks=4 passed=4 failed=0
19  | suite    | crash_consistency        | 1/cawp  | ✅ PASS    | 2/90s     | nodes_pass=1/1 checks=54 passed=54 failed=0
20  | suite    | dir_reuse_coherency      | 1/cawp  | ✅ PASS    | 78/120s   | nodes_pass=1/1 checks=170 passed=170 failed=0
21  | suite    | soak                     | 1/cawp  | ✅ PASS    | 32/60s    | dur=30s ops=1717 errs=0 dmesg_hits=0
22  | tooling  | mkfs_timing              | 1/cawp  | ✅ PASS    | 1/10s     | 263ms (threshold<=10000ms)
23  | tooling  | chk_clean                | 1/cawp  | ✅ PASS    | 0/10s     | rc=0 errors=0
24  | tooling  | online_resize            | 1/cawp  | ✅ PASS    | 2/25s     | pre=1695MB post=3743MB delta=2048MB/+2048MB data_intact=yes
25  | tooling  | dkms_install             | 1/cawp  | ✅ PASS    | 107/240s  | add=0 build=0 install=0 installed=yes remove=0 clean=yes
26  | tooling  | single_node_paired       | 1/cawp  | ✅ PASS    | 40/90s    | xfs=(3537/2664/3631/4913)ms mxfs=(2691/2809/3546/2969)ms round_ratios=60,76,97,105 ratio=86% files=8714/8714
27  | tooling  | fio_vs_xfs_baseline      | 1/cawp  | ✅ PASS    | 132/180s  | seqW=331/305MiB rounds=63,108,93,32→78% randW=33248/22981iops rounds=127,144,130,145→137% worst_write=78% [reads cache-bound: seqR 126% randR 105%]
28  | tooling  | cluster_ops_timing       | 1/cawp  | ✅ PASS    | 1/10s     | first=104ms rest=111ms umount=420ms
29  | tooling  | fault_io_error           | 1/cawp  | ✅ PASS    | 10/60s    | nodes_pass=1/1 eio=yes wms=6 bad_dmesg=0 remount=yes data_intact=yes chk_rc=0
30  | caw      | dlm_lock_correctness     | 1/cawp  | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 30 — 30 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=1 dlm=cawp]

=== MXFS TEST STATUS — conditions — nodes=2 dlm=cawp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 2/cawp  | ✅ PASS    | 0/300s    | skipped (marker matched 2/cawp)
2   | suite    | precond_readiness        | 2/cawp  | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 2/cawp  | ✅ PASS    | 42/120s   | nodes_pass=2/2 seqW=204MiB/s seqR=2511MiB/s randW=64429iops randR=71391iops
4   | suite    | fio_perf_vs_xfs          | 2/cawp  | ✅ PASS    | 1/10s     | seqW=78% seqR=135% randW=118% randR=168% worst(write)=78% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 2/cawp  | ✅ PASS    | 6/60s     | nodes_pass=2/2 checks=534 passed=534 failed=0
6   | suite    | strong_consistency       | 2/cawp  | ✅ PASS    | 1/30s     | nodes_pass=2/2 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 2/cawp  | ✅ PASS    | 2/30s     | nodes_pass=2/2 checks=140 passed=140 failed=0
8   | suite    | mmap_coherency           | 2/cawp  | ✅ PASS    | 1/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
9   | suite    | zero_silent_loss         | 2/cawp  | ✅ PASS    | 1/60s     | nodes_pass=2/2 checks=44 passed=44 failed=0
10  | suite    | dlm_fairness             | 2/cawp  | ✅ PASS    | 3/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 2/cawp  | ✅ PASS    | 3/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 2/cawp  | ✅ PASS    | 1/90s     | nodes_pass=2/2 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 2/cawp  | ✅ PASS    | 19/90s    | nodes_pass=2/2 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 2/cawp  | ✅ PASS    | 5/60s     | nodes_pass=2/2 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 2/cawp  | ✅ PASS    | 5/90s     | nodes_pass=2/2 checks=104 passed=104 failed=0
16  | suite    | dir_reuse_coherency      | 2/cawp  | ✅ PASS    | 102/120s  | nodes_pass=2/2 checks=135 passed=135 failed=0
17  | suite    | fence_during_write       | 2/cawp  | ✅ PASS    | 17/60s    | nodes_pass=2/2 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 2/cawp  | ✅ PASS    | 7/60s     | nodes_pass=2/2 checks=5 passed=5 failed=0
19  | suite    | soak                     | 2/cawp  | ✅ PASS    | 32/60s    | dur=30s ops=1102 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 2/cawp  | ✅ PASS    | 1/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=2 dlm=cawp]

=== MXFS TEST STATUS — conditions — nodes=4 dlm=cawp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 4/cawp  | ✅ PASS    | 0/300s    | skipped (marker matched 4/cawp)
2   | suite    | precond_readiness        | 4/cawp  | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 4/cawp  | ✅ PASS    | 24/120s   | nodes_pass=4/4 seqW=251MiB/s seqR=1823MiB/s randW=121935iops randR=139844iops
4   | suite    | fio_perf_vs_xfs          | 4/cawp  | ✅ PASS    | 0/10s     | seqW=89% seqR=98% randW=312% randR=329% worst(write)=89% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 4/cawp  | ✅ PASS    | 7/60s     | nodes_pass=4/4 checks=542 passed=542 failed=0
6   | suite    | strong_consistency       | 4/cawp  | ✅ PASS    | 2/30s     | nodes_pass=4/4 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 4/cawp  | ✅ PASS    | 3/30s     | nodes_pass=4/4 checks=80 passed=80 failed=0
8   | suite    | mmap_coherency           | 4/cawp  | ✅ PASS    | 1/30s     | nodes_pass=4/4 checks=7 passed=7 failed=0
9   | suite    | zero_silent_loss         | 4/cawp  | ✅ PASS    | 2/60s     | nodes_pass=4/4 checks=84 passed=84 failed=0
10  | suite    | dlm_fairness             | 4/cawp  | ✅ PASS    | 6/30s     | nodes_pass=4/4 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 4/cawp  | ✅ PASS    | 3/30s     | nodes_pass=4/4 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 4/cawp  | ✅ PASS    | 2/90s     | nodes_pass=4/4 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 4/cawp  | ✅ PASS    | 21/90s    | nodes_pass=4/4 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 4/cawp  | ✅ PASS    | 7/60s     | nodes_pass=4/4 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 4/cawp  | ✅ PASS    | 9/90s     | nodes_pass=4/4 checks=204 passed=204 failed=0
16  | suite    | dir_reuse_coherency      | 4/cawp  | ✅ PASS    | 103/120s  | nodes_pass=4/4 checks=128 passed=128 failed=0
17  | suite    | fence_during_write       | 4/cawp  | ✅ PASS    | 17/60s    | nodes_pass=4/4 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 4/cawp  | ✅ PASS    | 7/60s     | nodes_pass=4/4 checks=5 passed=5 failed=0
19  | suite    | soak                     | 4/cawp  | ✅ PASS    | 32/60s    | dur=30s ops=1104 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 4/cawp  | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=4 dlm=cawp]

=== MXFS TEST STATUS — conditions — nodes=8 dlm=cawp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 8/cawp  | ✅ PASS    | 0/300s    | skipped (marker matched 8/cawp)
2   | suite    | precond_readiness        | 8/cawp  | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 8/cawp  | ✅ PASS    | 23/120s   | nodes_pass=8/8 seqW=512MiB/s seqR=1728MiB/s randW=75222iops randR=210353iops
4   | suite    | fio_perf_vs_xfs          | 8/cawp  | ✅ PASS    | 1/10s     | seqW=110% seqR=100% randW=199% randR=534% worst(write)=110% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 8/cawp  | ✅ PASS    | 10/60s    | nodes_pass=8/8 checks=558 passed=558 failed=0
6   | suite    | strong_consistency       | 8/cawp  | ✅ PASS    | 1/30s     | nodes_pass=8/8 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 8/cawp  | ✅ PASS    | 3/30s     | nodes_pass=8/8 checks=56 passed=56 failed=0
8   | suite    | mmap_coherency           | 8/cawp  | ✅ PASS    | 1/30s     | nodes_pass=8/8 checks=11 passed=11 failed=0
9   | suite    | zero_silent_loss         | 8/cawp  | ✅ PASS    | 4/60s     | nodes_pass=8/8 checks=164 passed=164 failed=0
10  | suite    | dlm_fairness             | 8/cawp  | ✅ PASS    | 10/30s    | nodes_pass=8/8 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 8/cawp  | ✅ PASS    | 4/30s     | nodes_pass=8/8 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 8/cawp  | ✅ PASS    | 3/90s     | nodes_pass=8/8 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 8/cawp  | ✅ PASS    | 12/90s    | nodes_pass=8/8 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 8/cawp  | ✅ PASS    | 7/60s     | nodes_pass=8/8 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 8/cawp  | ✅ PASS    | 18/90s    | nodes_pass=8/8 checks=404 passed=404 failed=0
16  | suite    | dir_reuse_coherency      | 8/cawp  | ✅ PASS    | 101/120s  | nodes_pass=8/8 checks=114 passed=114 failed=0
17  | suite    | fence_during_write       | 8/cawp  | ✅ PASS    | 18/60s    | nodes_pass=8/8 checks=8 passed=8 failed=0
18  | suite    | fault_netpartition       | 8/cawp  | ✅ PASS    | 8/60s     | nodes_pass=8/8 checks=5 passed=5 failed=0
19  | suite    | soak                     | 8/cawp  | ✅ PASS    | 31/60s    | dur=30s ops=1665 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 8/cawp  | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=8 dlm=cawp]

=== MXFS TEST STATUS — conditions — nodes=16 dlm=cawp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 16/cawp | ✅ PASS    | 0/300s    | skipped (marker matched 16/cawp)
2   | suite    | precond_readiness        | 16/cawp | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 16/cawp | ✅ PASS    | 23/120s   | nodes_pass=16/16 seqW=3476MiB/s seqR=3662MiB/s randW=77094iops randR=373133iops
4   | suite    | fio_perf_vs_xfs          | 16/cawp | ✅ PASS    | 1/10s     | seqW=1687% seqR=212% randW=204% randR=947% worst(write)=204% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 16/cawp | ✅ PASS    | 15/60s    | nodes_pass=16/16 checks=590 passed=590 failed=0
6   | suite    | strong_consistency       | 16/cawp | ✅ PASS    | 3/30s     | nodes_pass=16/16 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 16/cawp | ✅ PASS    | 5/30s     | nodes_pass=16/16 checks=56 passed=56 failed=0
8   | suite    | mmap_coherency           | 16/cawp | ✅ PASS    | 3/30s     | nodes_pass=16/16 checks=19 passed=19 failed=0
9   | suite    | zero_silent_loss         | 16/cawp | ✅ PASS    | 10/60s    | nodes_pass=16/16 checks=324 passed=324 failed=0
10  | suite    | dlm_fairness             | 16/cawp | ✅ PASS    | 13/30s    | nodes_pass=16/16 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 16/cawp | ✅ PASS    | 4/30s     | nodes_pass=16/16 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 16/cawp | ✅ PASS    | 14/90s    | nodes_pass=16/16 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 16/cawp | ✅ PASS    | 9/90s     | nodes_pass=16/16 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 16/cawp | ✅ PASS    | 12/60s    | nodes_pass=16/16 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 16/cawp | ✅ PASS    | 35/90s    | nodes_pass=16/16 checks=354 passed=354 failed=0
16  | suite    | dir_reuse_coherency      | 16/cawp | ✅ PASS    | 108/120s  | nodes_pass=16/16 checks=93 passed=93 failed=0
17  | suite    | fence_during_write       | 16/cawp | ✅ PASS    | 20/60s    | nodes_pass=16/16 checks=8 passed=8 failed=0
18  | suite    | fault_netpartition       | 16/cawp | ✅ PASS    | 7/60s     | nodes_pass=16/16 checks=5 passed=5 failed=0
19  | suite    | soak                     | 16/cawp | ✅ PASS    | 32/60s    | dur=30s ops=1523 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 16/cawp | ✅ PASS    | 1/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=16 dlm=cawp]

=== MXFS TEST STATUS — conditions — nodes=32 dlm=cawp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 32/cawp | ✅ PASS    | 0/300s    | skipped (marker matched 32/cawp)
2   | suite    | precond_readiness        | 32/cawp | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 32/cawp | ✅ PASS    | 37/120s   | nodes_pass=32/32 seqW=5355MiB/s seqR=8315MiB/s randW=410302iops randR=579507iops
4   | suite    | fio_perf_vs_xfs          | 32/cawp | ✅ PASS    | 1/10s     | seqW=1617% seqR=493% randW=138% randR=1372% worst(write)=138% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 32/cawp | ✅ PASS    | 28/60s    | nodes_pass=32/32 checks=654 passed=654 failed=0
6   | suite    | strong_consistency       | 32/cawp | ✅ PASS    | 5/30s     | nodes_pass=32/32 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 32/cawp | ✅ PASS    | 7/30s     | nodes_pass=32/32 checks=80 passed=80 failed=0
8   | suite    | mmap_coherency           | 32/cawp | ✅ PASS    | 5/30s     | nodes_pass=32/32 checks=35 passed=35 failed=0
9   | suite    | zero_silent_loss         | 32/cawp | ✅ PASS    | 32/60s    | nodes_pass=32/32 checks=644 passed=644 failed=0
10  | suite    | dlm_fairness             | 32/cawp | ✅ PASS    | 20/30s    | nodes_pass=32/32 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 32/cawp | ✅ PASS    | 6/30s     | nodes_pass=32/32 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 32/cawp | ✅ PASS    | 16/90s    | nodes_pass=32/32 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 32/cawp | ✅ PASS    | 11/90s    | nodes_pass=32/32 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 32/cawp | ✅ PASS    | 41/60s    | nodes_pass=32/32 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 32/cawp | ✅ PASS    | 66/90s    | nodes_pass=32/32 checks=204 passed=204 failed=0
16  | suite    | dir_reuse_coherency      | 32/cawp | ✅ PASS    | 103/120s  | nodes_pass=32/32 checks=65 passed=65 failed=0
17  | suite    | fence_during_write       | 32/cawp | ✅ PASS    | 20/60s    | nodes_pass=32/32 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 32/cawp | ✅ PASS    | 10/60s    | nodes_pass=32/32 checks=5 passed=5 failed=0
19  | suite    | soak                     | 32/cawp | ✅ PASS    | 32/60s    | dur=30s ops=1039 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 32/cawp | ✅ PASS    | 1/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=32 dlm=cawp]



=== MXFS TEST STATUS — conditions — nodes=1 dlm=cawd ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 1/cawd  | ✅ PASS    | 0/300s    | skipped (marker matched 1/cawd)
2   | suite    | precond_readiness        | 1/cawd  | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | posix_single             | 1/cawd  | ✅ PASS    | 2/15s     | checks=29 passed=29 failed=0
4   | suite    | fsx                      | 1/cawd  | ✅ PASS    | 10/88s    | checks=2 passed=2 failed=0
5   | suite    | fio_verify               | 1/cawd  | ✅ PASS    | 4/42s     | checks=3 passed=3 failed=0
6   | suite    | integrity_filetypes      | 1/cawd  | ✅ PASS    | 2/10s     | checks=13 passed=13 failed=0
7   | suite    | fio_perf                 | 1/cawd  | ✅ PASS    | 13/120s   | nodes_pass=1/1 seqW=1805MiB/s seqR=621MiB/s randW=38596iops randR=40108iops
8   | suite    | fio_perf_vs_xfs          | 1/cawd  | ✅ PASS    | 0/10s     | seqW=113% seqR=112% randW=81% randR=87% worst(write)=81% (threshold>=70%, wsrc=xfs-baseline)
9   | suite    | cache_coherency          | 1/cawd  | ✅ PASS    | 2/60s     | nodes_pass=1/1 checks=530 passed=530 failed=0
10  | suite    | strong_consistency       | 1/cawd  | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=7 passed=7 failed=0
11  | suite    | posix_multi              | 1/cawd  | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=266 passed=266 failed=0
12  | suite    | mmap_coherency           | 1/cawd  | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=4 passed=4 failed=0
13  | suite    | zero_silent_loss         | 1/cawd  | ✅ PASS    | 1/60s     | nodes_pass=1/1 checks=24 passed=24 failed=0
14  | suite    | dlm_fairness             | 1/cawd  | ✅ PASS    | 1/30s     | nodes_pass=1/1 checks=5 passed=5 failed=0
15  | suite    | scaling_curve            | 1/cawd  | ✅ PASS    | 1/90s     | nodes_pass=1/1 checks=7 passed=7 failed=0
16  | suite    | dlm_scaling              | 1/cawd  | ✅ PASS    | 9/90s     | nodes_pass=1/1 checks=6 passed=6 failed=0
17  | suite    | rsync_paired             | 1/cawd  | ✅ PASS    | 3/60s     | nodes_pass=1/1 checks=6 passed=6 failed=0
18  | suite    | fault_enospc             | 1/cawd  | ✅ PASS    | 0/10s     | checks=4 passed=4 failed=0
19  | suite    | crash_consistency        | 1/cawd  | ✅ PASS    | 2/90s     | nodes_pass=1/1 checks=54 passed=54 failed=0
20  | suite    | dir_reuse_coherency      | 1/cawd  | ✅ PASS    | 77/120s   | nodes_pass=1/1 checks=170 passed=170 failed=0
21  | suite    | soak                     | 1/cawd  | ✅ PASS    | 31/60s    | dur=30s ops=1609 errs=0 dmesg_hits=0
22  | tooling  | mkfs_timing              | 1/cawd  | ✅ PASS    | 1/10s     | 288ms (threshold<=10000ms)
23  | tooling  | chk_clean                | 1/cawd  | ✅ PASS    | 0/10s     | rc=0 errors=0
24  | tooling  | online_resize            | 1/cawd  | ✅ PASS    | 3/25s     | pre=1695MB post=3743MB delta=2048MB/+2048MB data_intact=yes
25  | tooling  | dkms_install             | 1/cawd  | ✅ PASS    | 108/240s  | add=0 build=0 install=0 installed=yes remove=0 clean=yes
26  | tooling  | single_node_paired       | 1/cawd  | ✅ PASS    | 40/90s    | xfs=(3625/2633/2620/2916)ms mxfs=(2699/2657/2787/3196)ms round_ratios=74,100,106,109 ratio=103% files=8714/8714
27  | tooling  | fio_vs_xfs_baseline      | 1/cawd  | ✅ PASS    | 136/180s  | seqW=254/481MiB rounds=92,52,75,210→83% randW=27496/21530iops rounds=152,127,208,197→174% worst_write=83% [reads cache-bound: seqR 97% randR 90%]
28  | tooling  | cluster_ops_timing       | 1/cawd  | ✅ PASS    | 3/10s     | first=186ms rest=236ms umount=356ms
29  | tooling  | fault_io_error           | 1/cawd  | ✅ PASS    | 11/60s    | nodes_pass=1/1 eio=yes wms=7 bad_dmesg=0 remount=yes data_intact=yes chk_rc=0
30  | caw      | dlm_lock_correctness     | 1/cawd  | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 30 — 30 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=1 dlm=cawd]

=== MXFS TEST STATUS — conditions — nodes=2 dlm=cawd ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 2/cawd  | ✅ PASS    | 0/300s    | skipped (marker matched 2/cawd)
2   | suite    | precond_readiness        | 2/cawd  | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 2/cawd  | ✅ PASS    | 21/120s   | nodes_pass=2/2 seqW=1939MiB/s seqR=1057MiB/s randW=61692iops randR=80466iops
4   | suite    | fio_perf_vs_xfs          | 2/cawd  | ✅ PASS    | 1/10s     | seqW=435% seqR=192% randW=92% randR=174% worst(write)=92% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 2/cawd  | ✅ PASS    | 6/60s     | nodes_pass=2/2 checks=534 passed=534 failed=0
6   | suite    | strong_consistency       | 2/cawd  | ✅ PASS    | 1/30s     | nodes_pass=2/2 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 2/cawd  | ✅ PASS    | 2/30s     | nodes_pass=2/2 checks=140 passed=140 failed=0
8   | suite    | mmap_coherency           | 2/cawd  | ✅ PASS    | 0/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
9   | suite    | zero_silent_loss         | 2/cawd  | ✅ PASS    | 1/60s     | nodes_pass=2/2 checks=44 passed=44 failed=0
10  | suite    | dlm_fairness             | 2/cawd  | ✅ PASS    | 3/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 2/cawd  | ✅ PASS    | 3/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 2/cawd  | ✅ PASS    | 3/90s     | nodes_pass=2/2 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 2/cawd  | ✅ PASS    | 9/90s     | nodes_pass=2/2 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 2/cawd  | ✅ PASS    | 5/60s     | nodes_pass=2/2 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 2/cawd  | ✅ PASS    | 5/90s     | nodes_pass=2/2 checks=104 passed=104 failed=0
16  | suite    | dir_reuse_coherency      | 2/cawd  | ✅ PASS    | 103/120s  | nodes_pass=2/2 checks=163 passed=163 failed=0
17  | suite    | fence_during_write       | 2/cawd  | ✅ PASS    | 16/60s    | nodes_pass=2/2 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 2/cawd  | ✅ PASS    | 7/60s     | nodes_pass=2/2 checks=5 passed=5 failed=0
19  | suite    | soak                     | 2/cawd  | ✅ PASS    | 31/60s    | dur=30s ops=1655 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 2/cawd  | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=2 dlm=cawd]

=== MXFS TEST STATUS — conditions — nodes=4 dlm=cawd ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 4/cawd  | ✅ PASS    | 0/300s    | skipped (marker matched 4/cawd)
2   | suite    | precond_readiness        | 4/cawd  | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 4/cawd  | ✅ PASS    | 22/120s   | nodes_pass=4/4 seqW=322MiB/s seqR=1692MiB/s randW=86199iops randR=160715iops
4   | suite    | fio_perf_vs_xfs          | 4/cawd  | ✅ PASS    | 1/10s     | seqW=182% seqR=307% randW=121% randR=348% worst(write)=121% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 4/cawd  | ✅ PASS    | 7/60s     | nodes_pass=4/4 checks=542 passed=542 failed=0
6   | suite    | strong_consistency       | 4/cawd  | ✅ PASS    | 1/30s     | nodes_pass=4/4 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 4/cawd  | ✅ PASS    | 3/30s     | nodes_pass=4/4 checks=80 passed=80 failed=0
8   | suite    | mmap_coherency           | 4/cawd  | ✅ PASS    | 1/30s     | nodes_pass=4/4 checks=7 passed=7 failed=0
9   | suite    | zero_silent_loss         | 4/cawd  | ✅ PASS    | 2/60s     | nodes_pass=4/4 checks=84 passed=84 failed=0
10  | suite    | dlm_fairness             | 4/cawd  | ✅ PASS    | 5/30s     | nodes_pass=4/4 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 4/cawd  | ✅ PASS    | 3/30s     | nodes_pass=4/4 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 4/cawd  | ✅ PASS    | 4/90s     | nodes_pass=4/4 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 4/cawd  | ✅ PASS    | 10/90s    | nodes_pass=4/4 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 4/cawd  | ✅ PASS    | 5/60s     | nodes_pass=4/4 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 4/cawd  | ✅ PASS    | 8/90s     | nodes_pass=4/4 checks=204 passed=204 failed=0
16  | suite    | dir_reuse_coherency      | 4/cawd  | ✅ PASS    | 103/120s  | nodes_pass=4/4 checks=149 passed=149 failed=0
17  | suite    | fence_during_write       | 4/cawd  | ✅ PASS    | 18/60s    | nodes_pass=4/4 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 4/cawd  | ✅ PASS    | 7/60s     | nodes_pass=4/4 checks=5 passed=5 failed=0
19  | suite    | soak                     | 4/cawd  | ✅ PASS    | 32/60s    | dur=30s ops=1346 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 4/cawd  | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=4 dlm=cawd]

=== MXFS TEST STATUS — conditions — nodes=8 dlm=cawd ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 8/cawd  | ✅ PASS    | 0/300s    | skipped (marker matched 8/cawd)
2   | suite    | precond_readiness        | 8/cawd  | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 8/cawd  | ✅ PASS    | 18/120s   | nodes_pass=8/8 seqW=2010MiB/s seqR=2333MiB/s randW=77218iops randR=238120iops
4   | suite    | fio_perf_vs_xfs          | 8/cawd  | ✅ PASS    | 1/10s     | seqW=1005% seqR=424% randW=121% randR=516% worst(write)=121% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 8/cawd  | ✅ PASS    | 12/60s    | nodes_pass=8/8 checks=558 passed=558 failed=0
6   | suite    | strong_consistency       | 8/cawd  | ✅ PASS    | 1/30s     | nodes_pass=8/8 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 8/cawd  | ✅ PASS    | 4/30s     | nodes_pass=8/8 checks=56 passed=56 failed=0
8   | suite    | mmap_coherency           | 8/cawd  | ✅ PASS    | 1/30s     | nodes_pass=8/8 checks=11 passed=11 failed=0
9   | suite    | zero_silent_loss         | 8/cawd  | ✅ PASS    | 3/60s     | nodes_pass=8/8 checks=164 passed=164 failed=0
10  | suite    | dlm_fairness             | 8/cawd  | ✅ PASS    | 8/30s     | nodes_pass=8/8 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 8/cawd  | ✅ PASS    | 3/30s     | nodes_pass=8/8 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 8/cawd  | ✅ PASS    | 4/90s     | nodes_pass=8/8 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 8/cawd  | ✅ PASS    | 22/90s    | nodes_pass=8/8 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 8/cawd  | ✅ PASS    | 11/60s    | nodes_pass=8/8 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 8/cawd  | ✅ PASS    | 10/90s    | nodes_pass=8/8 checks=404 passed=404 failed=0
16  | suite    | dir_reuse_coherency      | 8/cawd  | ✅ PASS    | 101/120s  | nodes_pass=8/8 checks=107 passed=107 failed=0
17  | suite    | fence_during_write       | 8/cawd  | ✅ PASS    | 19/60s    | nodes_pass=8/8 checks=8 passed=8 failed=0
18  | suite    | fault_netpartition       | 8/cawd  | ✅ PASS    | 8/60s     | nodes_pass=8/8 checks=5 passed=5 failed=0
19  | suite    | soak                     | 8/cawd  | ✅ PASS    | 31/60s    | dur=30s ops=1347 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 8/cawd  | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=8 dlm=cawd]

=== MXFS TEST STATUS — conditions — nodes=16 dlm=cawd ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 16/cawd | ✅ PASS    | 0/300s    | skipped (marker matched 16/cawd)
2   | suite    | precond_readiness        | 16/cawd | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 16/cawd | ✅ PASS    | 22/120s   | nodes_pass=16/16 seqW=1970MiB/s seqR=3099MiB/s randW=51464iops randR=396402iops
4   | suite    | fio_perf_vs_xfs          | 16/cawd | ✅ PASS    | 1/10s     | seqW=778% seqR=563% randW=100% randR=860% worst(write)=100% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 16/cawd | ✅ PASS    | 16/60s    | nodes_pass=16/16 checks=590 passed=590 failed=0
6   | suite    | strong_consistency       | 16/cawd | ✅ PASS    | 3/30s     | nodes_pass=16/16 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 16/cawd | ✅ PASS    | 4/30s     | nodes_pass=16/16 checks=56 passed=56 failed=0
8   | suite    | mmap_coherency           | 16/cawd | ✅ PASS    | 3/30s     | nodes_pass=16/16 checks=19 passed=19 failed=0
9   | suite    | zero_silent_loss         | 16/cawd | ✅ PASS    | 10/60s    | nodes_pass=16/16 checks=324 passed=324 failed=0
10  | suite    | dlm_fairness             | 16/cawd | ✅ PASS    | 14/30s    | nodes_pass=16/16 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 16/cawd | ✅ PASS    | 4/30s     | nodes_pass=16/16 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 16/cawd | ✅ PASS    | 4/90s     | nodes_pass=16/16 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 16/cawd | ✅ PASS    | 17/90s    | nodes_pass=16/16 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 16/cawd | ✅ PASS    | 11/60s    | nodes_pass=16/16 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 16/cawd | ✅ PASS    | 31/90s    | nodes_pass=16/16 checks=354 passed=354 failed=0
16  | suite    | dir_reuse_coherency      | 16/cawd | ✅ PASS    | 105/120s  | nodes_pass=16/16 checks=93 passed=93 failed=0
17  | suite    | fence_during_write       | 16/cawd | ✅ PASS    | 20/60s    | nodes_pass=16/16 checks=8 passed=8 failed=0
18  | suite    | fault_netpartition       | 16/cawd | ✅ PASS    | 8/60s     | nodes_pass=16/16 checks=5 passed=5 failed=0
19  | suite    | soak                     | 16/cawd | ✅ PASS    | 32/60s    | dur=30s ops=1585 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 16/cawd | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=16 dlm=cawd]

=== MXFS TEST STATUS — conditions — nodes=32 dlm=cawd ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 32/cawd | ✅ PASS    | 0/300s    | skipped (marker matched 32/cawd)
2   | suite    | precond_readiness        | 32/cawd | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 32/cawd | ✅ PASS    | 34/120s   | nodes_pass=32/32 seqW=7476MiB/s seqR=7306MiB/s randW=280329iops randR=294258iops
4   | suite    | fio_perf_vs_xfs          | 32/cawd | ✅ PASS    | 0/10s     | seqW=1048% seqR=1328% randW=487% randR=638% worst(write)=487% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 32/cawd | ✅ PASS    | 24/60s    | nodes_pass=32/32 checks=654 passed=654 failed=0
6   | suite    | strong_consistency       | 32/cawd | ✅ PASS    | 4/30s     | nodes_pass=32/32 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 32/cawd | ✅ PASS    | 7/30s     | nodes_pass=32/32 checks=80 passed=80 failed=0
8   | suite    | mmap_coherency           | 32/cawd | ✅ PASS    | 5/30s     | nodes_pass=32/32 checks=35 passed=35 failed=0
9   | suite    | zero_silent_loss         | 32/cawd | ✅ PASS    | 27/60s    | nodes_pass=32/32 checks=644 passed=644 failed=0
10  | suite    | dlm_fairness             | 32/cawd | ✅ PASS    | 17/30s    | nodes_pass=32/32 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 32/cawd | ✅ PASS    | 5/30s     | nodes_pass=32/32 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 32/cawd | ✅ PASS    | 22/90s    | nodes_pass=32/32 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 32/cawd | ✅ PASS    | 60/90s    | nodes_pass=32/32 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 32/cawd | ✅ PASS    | 22/60s    | nodes_pass=32/32 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 32/cawd | ✅ PASS    | 65/90s    | nodes_pass=32/32 checks=204 passed=204 failed=0
16  | suite    | dir_reuse_coherency      | 32/cawd | ✅ PASS    | 110/120s  | nodes_pass=32/32 checks=65 passed=65 failed=0
17  | suite    | fence_during_write       | 32/cawd | ✅ PASS    | 20/60s    | nodes_pass=32/32 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 32/cawd | ✅ PASS    | 10/60s    | nodes_pass=32/32 checks=5 passed=5 failed=0
19  | suite    | soak                     | 32/cawd | ✅ PASS    | 31/60s    | dur=30s ops=1080 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 32/cawd | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=32 dlm=cawd]



=== MXFS TEST STATUS — conditions — nodes=1 dlm=caw ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 1/caw   | ✅ PASS    | 0/300s    | skipped (marker matched 1/caw)
2   | suite    | precond_readiness        | 1/caw   | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | posix_single             | 1/caw   | ✅ PASS    | 1/15s     | checks=29 passed=29 failed=0
4   | suite    | fsx                      | 1/caw   | ✅ PASS    | 9/88s     | checks=2 passed=2 failed=0
5   | suite    | fio_verify               | 1/caw   | ✅ PASS    | 3/42s     | checks=3 passed=3 failed=0
6   | suite    | integrity_filetypes      | 1/caw   | ✅ PASS    | 3/10s     | checks=13 passed=13 failed=0
7   | suite    | fio_perf                 | 1/caw   | ✅ PASS    | 15/120s   | nodes_pass=1/1 seqW=1517MiB/s seqR=596MiB/s randW=34456iops randR=39864iops
8   | suite    | fio_perf_vs_xfs          | 1/caw   | ✅ PASS    | 0/10s     | seqW=692% seqR=38% randW=85% randR=145% worst(write)=85% (threshold>=70%, wsrc=raw-ceiling)
9   | suite    | cache_coherency          | 1/caw   | ✅ PASS    | 2/60s     | nodes_pass=1/1 checks=530 passed=530 failed=0
10  | suite    | strong_consistency       | 1/caw   | ✅ PASS    | 1/30s     | nodes_pass=1/1 checks=7 passed=7 failed=0
11  | suite    | posix_multi              | 1/caw   | ✅ PASS    | 1/30s     | nodes_pass=1/1 checks=266 passed=266 failed=0
12  | suite    | mmap_coherency           | 1/caw   | ✅ PASS    | 1/30s     | nodes_pass=1/1 checks=4 passed=4 failed=0
13  | suite    | zero_silent_loss         | 1/caw   | ✅ PASS    | 1/60s     | nodes_pass=1/1 checks=24 passed=24 failed=0
14  | suite    | dlm_fairness             | 1/caw   | ✅ PASS    | 1/30s     | nodes_pass=1/1 checks=5 passed=5 failed=0
15  | suite    | scaling_curve            | 1/caw   | ✅ PASS    | 1/90s     | nodes_pass=1/1 checks=7 passed=7 failed=0
16  | suite    | dlm_scaling              | 1/caw   | ✅ PASS    | 10/90s    | nodes_pass=1/1 checks=6 passed=6 failed=0
17  | suite    | rsync_paired             | 1/caw   | ✅ PASS    | 3/60s     | nodes_pass=1/1 checks=6 passed=6 failed=0
18  | suite    | fault_enospc             | 1/caw   | ✅ PASS    | 0/10s     | checks=4 passed=4 failed=0
19  | suite    | crash_consistency        | 1/caw   | ✅ PASS    | 2/90s     | nodes_pass=1/1 checks=54 passed=54 failed=0
20  | suite    | dir_reuse_coherency      | 1/caw   | ✅ PASS    | 77/120s   | nodes_pass=1/1 checks=170 passed=170 failed=0
21  | suite    | soak                     | 1/caw   | ✅ PASS    | 31/60s    | dur=30s ops=1569 errs=0 dmesg_hits=0
22  | tooling  | mkfs_timing              | 1/caw   | ✅ PASS    | 2/10s     | 828ms (threshold<=10000ms)
23  | tooling  | chk_clean                | 1/caw   | ✅ PASS    | 0/10s     | rc=0 errors=0
24  | tooling  | online_resize            | 1/caw   | ✅ PASS    | 2/25s     | pre=1695MB post=3743MB delta=2048MB/+2048MB data_intact=yes
25  | tooling  | dkms_install             | 1/caw   | ✅ PASS    | 92/240s   | add=0 build=0 install=0 installed=yes remove=0 clean=yes
26  | tooling  | single_node_paired       | 1/caw   | ✅ PASS    | 41/90s    | xfs=(4419/3194/3356/3072)ms mxfs=(2895/2858/3449/2868)ms round_ratios=65,89,93,102 ratio=91% files=8714/8714
27  | tooling  | fio_vs_xfs_baseline      | 1/caw   | ✅ PASS    | 129/180s  | seqW=335/421MiB rounds=170,79,108,31→93% randW=26442/16642iops rounds=159,158,121,164→158% worst_write=93% [reads cache-bound: seqR 126% randR 122%]
28  | tooling  | cluster_ops_timing       | 1/caw   | ✅ PASS    | 1/10s     | first=109ms rest=118ms umount=429ms
29  | tooling  | fault_io_error           | 1/caw   | ✅ PASS    | 10/60s    | nodes_pass=1/1 eio=yes wms=6 bad_dmesg=0 remount=yes data_intact=yes chk_rc=0
30  | caw      | dlm_lock_correctness     | 1/caw   | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 30 — 30 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=1 dlm=caw]

=== MXFS TEST STATUS — conditions — nodes=2 dlm=caw ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 2/caw   | ✅ PASS    | 0/300s    | skipped (marker matched 2/caw)
2   | suite    | precond_readiness        | 2/caw   | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 2/caw   | ✅ PASS    | 34/120s   | nodes_pass=2/2 seqW=318MiB/s seqR=1164MiB/s randW=67166iops randR=58253iops
4   | suite    | fio_perf_vs_xfs          | 2/caw   | ✅ PASS    | 1/10s     | seqW=190% seqR=75% randW=130% randR=212% worst(write)=130% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 2/caw   | ✅ PASS    | 5/60s     | nodes_pass=2/2 checks=534 passed=534 failed=0
6   | suite    | strong_consistency       | 2/caw   | ✅ PASS    | 1/30s     | nodes_pass=2/2 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 2/caw   | ✅ PASS    | 2/30s     | nodes_pass=2/2 checks=140 passed=140 failed=0
8   | suite    | mmap_coherency           | 2/caw   | ✅ PASS    | 1/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
9   | suite    | zero_silent_loss         | 2/caw   | ✅ PASS    | 1/60s     | nodes_pass=2/2 checks=44 passed=44 failed=0
10  | suite    | dlm_fairness             | 2/caw   | ✅ PASS    | 4/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 2/caw   | ✅ PASS    | 3/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 2/caw   | ✅ PASS    | 3/90s     | nodes_pass=2/2 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 2/caw   | ✅ PASS    | 20/90s    | nodes_pass=2/2 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 2/caw   | ✅ PASS    | 6/60s     | nodes_pass=2/2 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 2/caw   | ✅ PASS    | 4/90s     | nodes_pass=2/2 checks=104 passed=104 failed=0
16  | suite    | dir_reuse_coherency      | 2/caw   | ✅ PASS    | 103/120s  | nodes_pass=2/2 checks=149 passed=149 failed=0
17  | suite    | fence_during_write       | 2/caw   | ✅ PASS    | 17/60s    | nodes_pass=2/2 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 2/caw   | ✅ PASS    | 7/60s     | nodes_pass=2/2 checks=5 passed=5 failed=0
19  | suite    | soak                     | 2/caw   | ✅ PASS    | 31/60s    | dur=30s ops=1191 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 2/caw   | ✅ PASS    | 1/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=2 dlm=caw]

=== MXFS TEST STATUS — conditions — nodes=4 dlm=caw ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 4/caw   | ✅ PASS    | 0/300s    | skipped (marker matched 4/caw)
2   | suite    | precond_readiness        | 4/caw   | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 4/caw   | ✅ PASS    | 21/120s   | nodes_pass=4/4 seqW=778MiB/s seqR=1727MiB/s randW=64925iops randR=125088iops
4   | suite    | fio_perf_vs_xfs          | 4/caw   | ✅ PASS    | 0/10s     | seqW=471% seqR=111% randW=181% randR=455% worst(write)=181% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 4/caw   | ✅ PASS    | 8/60s     | nodes_pass=4/4 checks=542 passed=542 failed=0
6   | suite    | strong_consistency       | 4/caw   | ✅ PASS    | 1/30s     | nodes_pass=4/4 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 4/caw   | ✅ PASS    | 2/30s     | nodes_pass=4/4 checks=80 passed=80 failed=0
8   | suite    | mmap_coherency           | 4/caw   | ✅ PASS    | 1/30s     | nodes_pass=4/4 checks=7 passed=7 failed=0
9   | suite    | zero_silent_loss         | 4/caw   | ✅ PASS    | 2/60s     | nodes_pass=4/4 checks=84 passed=84 failed=0
10  | suite    | dlm_fairness             | 4/caw   | ✅ PASS    | 5/30s     | nodes_pass=4/4 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 4/caw   | ✅ PASS    | 3/30s     | nodes_pass=4/4 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 4/caw   | ✅ PASS    | 2/90s     | nodes_pass=4/4 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 4/caw   | ✅ PASS    | 11/90s    | nodes_pass=4/4 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 4/caw   | ✅ PASS    | 6/60s     | nodes_pass=4/4 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 4/caw   | ✅ PASS    | 8/90s     | nodes_pass=4/4 checks=204 passed=204 failed=0
16  | suite    | dir_reuse_coherency      | 4/caw   | ✅ PASS    | 105/120s  | nodes_pass=4/4 checks=156 passed=156 failed=0
17  | suite    | fence_during_write       | 4/caw   | ✅ PASS    | 16/60s    | nodes_pass=4/4 checks=8 passed=8 failed=0
18  | suite    | fault_netpartition       | 4/caw   | ✅ PASS    | 7/60s     | nodes_pass=4/4 checks=5 passed=5 failed=0
19  | suite    | soak                     | 4/caw   | ✅ PASS    | 32/60s    | dur=30s ops=1281 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 4/caw   | ✅ PASS    | 1/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=4 dlm=caw]

=== MXFS TEST STATUS — conditions — nodes=8 dlm=caw ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 8/caw   | ✅ PASS    | 0/300s    | skipped (marker matched 8/caw)
2   | suite    | precond_readiness        | 8/caw   | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 8/caw   | ✅ PASS    | 33/120s   | nodes_pass=8/8 seqW=218MiB/s seqR=2104MiB/s randW=48977iops randR=181333iops
4   | suite    | fio_perf_vs_xfs          | 8/caw   | ✅ PASS    | 0/10s     | seqW=102% seqR=136% randW=94% randR=660% worst(write)=94% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 8/caw   | ✅ PASS    | 8/60s     | nodes_pass=8/8 checks=558 passed=558 failed=0
6   | suite    | strong_consistency       | 8/caw   | ✅ PASS    | 2/30s     | nodes_pass=8/8 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 8/caw   | ✅ PASS    | 3/30s     | nodes_pass=8/8 checks=56 passed=56 failed=0
8   | suite    | mmap_coherency           | 8/caw   | ✅ PASS    | 1/30s     | nodes_pass=8/8 checks=11 passed=11 failed=0
9   | suite    | zero_silent_loss         | 8/caw   | ✅ PASS    | 4/60s     | nodes_pass=8/8 checks=164 passed=164 failed=0
10  | suite    | dlm_fairness             | 8/caw   | ✅ PASS    | 10/30s    | nodes_pass=8/8 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 8/caw   | ✅ PASS    | 3/30s     | nodes_pass=8/8 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 8/caw   | ✅ PASS    | 3/90s     | nodes_pass=8/8 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 8/caw   | ✅ PASS    | 23/90s    | nodes_pass=8/8 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 8/caw   | ✅ PASS    | 7/60s     | nodes_pass=8/8 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 8/caw   | ✅ PASS    | 18/90s    | nodes_pass=8/8 checks=404 passed=404 failed=0
16  | suite    | dir_reuse_coherency      | 8/caw   | ✅ PASS    | 107/120s  | nodes_pass=8/8 checks=107 passed=107 failed=0
17  | suite    | fence_during_write       | 8/caw   | ✅ PASS    | 17/60s    | nodes_pass=8/8 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 8/caw   | ✅ PASS    | 8/60s     | nodes_pass=8/8 checks=5 passed=5 failed=0
19  | suite    | soak                     | 8/caw   | ✅ PASS    | 31/60s    | dur=30s ops=1135 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 8/caw   | ✅ PASS    | 1/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=8 dlm=caw]

=== MXFS TEST STATUS — conditions — nodes=16 dlm=caw ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 16/caw  | ✅ PASS    | 0/300s    | skipped (marker matched 16/caw)
2   | suite    | precond_readiness        | 16/caw  | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 16/caw  | ✅ PASS    | 31/120s   | nodes_pass=16/16 seqW=1864MiB/s seqR=2375MiB/s randW=114948iops randR=396647iops
4   | suite    | fio_perf_vs_xfs          | 16/caw  | ✅ PASS    | 0/10s     | seqW=549% seqR=154% randW=210% randR=1445% worst(write)=210% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 16/caw  | ✅ PASS    | 15/60s    | nodes_pass=16/16 checks=590 passed=590 failed=0
6   | suite    | strong_consistency       | 16/caw  | ✅ PASS    | 3/30s     | nodes_pass=16/16 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 16/caw  | ✅ PASS    | 4/30s     | nodes_pass=16/16 checks=56 passed=56 failed=0
8   | suite    | mmap_coherency           | 16/caw  | ✅ PASS    | 2/30s     | nodes_pass=16/16 checks=19 passed=19 failed=0
9   | suite    | zero_silent_loss         | 16/caw  | ✅ PASS    | 10/60s    | nodes_pass=16/16 checks=324 passed=324 failed=0
10  | suite    | dlm_fairness             | 16/caw  | ✅ PASS    | 16/30s    | nodes_pass=16/16 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 16/caw  | ✅ PASS    | 5/30s     | nodes_pass=16/16 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 16/caw  | ✅ PASS    | 4/90s     | nodes_pass=16/16 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 16/caw  | ✅ PASS    | 34/90s    | nodes_pass=16/16 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 16/caw  | ✅ PASS    | 14/60s    | nodes_pass=16/16 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 16/caw  | ✅ PASS    | 32/90s    | nodes_pass=16/16 checks=354 passed=354 failed=0
16  | suite    | dir_reuse_coherency      | 16/caw  | ✅ PASS    | 100/120s  | nodes_pass=16/16 checks=79 passed=79 failed=0
17  | suite    | fence_during_write       | 16/caw  | ✅ PASS    | 20/60s    | nodes_pass=16/16 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 16/caw  | ✅ PASS    | 9/60s     | nodes_pass=16/16 checks=5 passed=5 failed=0
19  | suite    | soak                     | 16/caw  | ✅ PASS    | 32/60s    | dur=30s ops=1173 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 16/caw  | ✅ PASS    | 1/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=16 dlm=caw]

=== MXFS TEST STATUS — conditions — nodes=32 dlm=caw ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 32/caw  | ✅ PASS    | 0/300s    | skipped (marker matched 32/caw)
2   | suite    | precond_readiness        | 32/caw  | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 32/caw  | ✅ PASS    | 48/120s   | nodes_pass=32/32 seqW=2864MiB/s seqR=5695MiB/s randW=96881iops randR=596022iops
4   | suite    | fio_perf_vs_xfs          | 32/caw  | ✅ PASS    | 1/10s     | seqW=501% seqR=369% randW=144% randR=2171% worst(write)=144% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 32/caw  | ✅ PASS    | 29/60s    | nodes_pass=32/32 checks=654 passed=654 failed=0
6   | suite    | strong_consistency       | 32/caw  | ✅ PASS    | 4/30s     | nodes_pass=32/32 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 32/caw  | ✅ PASS    | 7/30s     | nodes_pass=32/32 checks=80 passed=80 failed=0
8   | suite    | mmap_coherency           | 32/caw  | ✅ PASS    | 5/30s     | nodes_pass=32/32 checks=35 passed=35 failed=0
9   | suite    | zero_silent_loss         | 32/caw  | ✅ PASS    | 34/60s    | nodes_pass=32/32 checks=644 passed=644 failed=0
10  | suite    | dlm_fairness             | 32/caw  | ✅ PASS    | 22/30s    | nodes_pass=32/32 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 32/caw  | ✅ PASS    | 6/30s     | nodes_pass=32/32 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 32/caw  | ✅ PASS    | 43/90s    | nodes_pass=32/32 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 32/caw  | ✅ PASS    | 50/90s    | nodes_pass=32/32 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 32/caw  | ✅ PASS    | 37/60s    | nodes_pass=32/32 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 32/caw  | ✅ PASS    | 69/90s    | nodes_pass=32/32 checks=204 passed=204 failed=0
16  | suite    | dir_reuse_coherency      | 32/caw  | ❌ FAIL    | 103/120s  | nodes_pass=0/32 states:FAIL=32 checks=51 passed=50 failed=1
17  | suite    | fence_during_write       | 32/caw  | ❌ FAIL    | 0/60s     | pre-assert
18  | suite    | fault_netpartition       | 32/caw  | ✅ PASS    | 10/60s    | nodes_pass=32/32 checks=5 passed=5 failed=0
19  | suite    | soak                     | 32/caw  | ✅ PASS    | 31/60s    | dur=30s ops=854 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 32/caw  | ✅ PASS    | 1/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 18 PASS, 2 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=32 dlm=caw]
```
