```text



=== MXFS TEST STATUS — conditions — nodes=1 dlm=tcp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 1/tcp   | ✅ PASS    | 0/300s    | skipped (marker matched 1/tcp)
2   | suite    | precond_readiness        | 1/tcp   | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | posix_single             | 1/tcp   | ✅ PASS    | 1/15s     | checks=29 passed=29 failed=0
4   | suite    | fsx                      | 1/tcp   | ✅ PASS    | 49/88s    | checks=2 passed=2 failed=0
5   | suite    | fio_verify               | 1/tcp   | ✅ PASS    | 24/42s    | checks=3 passed=3 failed=0
6   | suite    | integrity_filetypes      | 1/tcp   | ✅ PASS    | 5/10s     | checks=13 passed=13 failed=0
7   | suite    | fio_perf                 | 1/tcp   | ✅ PASS    | 69/120s   | nodes_pass=1/1 seqW=731MiB/s seqR=10893MiB/s randW=998iops randR=102721iops
8   | suite    | fio_perf_vs_xfs          | 1/tcp   | ✅ PASS    | 1/10s     | seqW=181% seqR=147% randW=101% randR=89% worst(write)=101% (threshold>=70%, wsrc=raw-ceiling)
9   | suite    | cache_coherency          | 1/tcp   | ✅ PASS    | 1/60s     | nodes_pass=1/1 checks=530 passed=530 failed=0
10  | suite    | strong_consistency       | 1/tcp   | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=7 passed=7 failed=0
11  | suite    | posix_multi              | 1/tcp   | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=266 passed=266 failed=0
12  | suite    | mmap_coherency           | 1/tcp   | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=4 passed=4 failed=0
13  | suite    | zero_silent_loss         | 1/tcp   | ✅ PASS    | 1/60s     | nodes_pass=1/1 checks=24 passed=24 failed=0
14  | suite    | dlm_fairness             | 1/tcp   | ✅ PASS    | 1/30s     | nodes_pass=1/1 checks=5 passed=5 failed=0
15  | suite    | scaling_curve            | 1/tcp   | ✅ PASS    | 2/90s     | nodes_pass=1/1 checks=7 passed=7 failed=0
16  | suite    | dlm_scaling              | 1/tcp   | ✅ PASS    | 13/90s    | nodes_pass=1/1 checks=6 passed=6 failed=0
17  | suite    | rsync_paired             | 1/tcp   | ✅ PASS    | 2/60s     | nodes_pass=1/1 checks=6 passed=6 failed=0
18  | suite    | fault_enospc             | 1/tcp   | ✅ PASS    | 2/10s     | checks=4 passed=4 failed=0
19  | suite    | crash_consistency        | 1/tcp   | ✅ PASS    | 2/90s     | nodes_pass=1/1 checks=54 passed=54 failed=0
20  | suite    | dir_reuse_coherency      | 1/tcp   | ✅ PASS    | 52/120s   | nodes_pass=1/1 checks=170 passed=170 failed=0
21  | suite    | soak                     | 1/tcp   | ✅ PASS    | 31/60s    | dur=30s ops=1733 errs=0 dmesg_hits=0
22  | tooling  | mkfs_timing              | 1/tcp   | ✅ PASS    | 2/10s     | 1288ms (threshold<=10000ms)
23  | tooling  | chk_clean                | 1/tcp   | ✅ PASS    | 1/10s     | rc=0 errors=0
24  | tooling  | online_resize            | 1/tcp   | ✅ PASS    | 2/25s     | pre=1695MB post=3743MB delta=2048MB/+2048MB data_intact=yes
25  | tooling  | dkms_install             | 1/tcp   | ✅ PASS    | 98/240s   | add=0 build=0 install=0 installed=yes remove=0 clean=yes
26  | tooling  | single_node_paired       | 1/tcp   | ✅ PASS    | 50/90s    | xfs=(4836/3415/3019/2960)ms mxfs=(3941/3026/4926/3334)ms round_ratios=81,88,112,163 ratio=100% files=8714/8714
27  | tooling  | fio_vs_xfs_baseline      | 1/tcp   | ✅ PASS    | 130/180s  | seqW=592/259MiB rounds=63,228,251,23→145% randW=720/901iops rounds=96,79,134,115→105% worst_write=105% [reads cache-bound: seqR 112% randR 95%]
28  | tooling  | cluster_ops_timing       | 1/tcp   | ✅ PASS    | 3/10s     | first=132ms rest=130ms umount=387ms
29  | tooling  | fault_io_error           | 1/tcp   | ✅ PASS    | 2/60s     | nodes_pass=1/1 eio=yes wms=6 bad_dmesg=0 remount=yes data_intact=yes chk_rc=0
------------------------------------------------------------------------------------------
Total: 29 — 29 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=1 dlm=tcp]

=== MXFS TEST STATUS — conditions — nodes=2 dlm=tcp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 2/tcp   | ✅ PASS    | 0/300s    | skipped (marker matched 2/tcp)
2   | suite    | precond_readiness        | 2/tcp   | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 2/tcp   | ✅ PASS    | 86/120s   | nodes_pass=2/2 seqW=549MiB/s seqR=22023MiB/s randW=902iops randR=188523iops
4   | suite    | fio_perf_vs_xfs          | 2/tcp   | ✅ PASS    | 0/10s     | seqW=150% seqR=176% randW=80% randR=165% worst(write)=80% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 2/tcp   | ✅ PASS    | 4/60s     | nodes_pass=2/2 checks=534 passed=534 failed=0
6   | suite    | strong_consistency       | 2/tcp   | ✅ PASS    | 1/30s     | nodes_pass=2/2 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 2/tcp   | ✅ PASS    | 2/30s     | nodes_pass=2/2 checks=140 passed=140 failed=0
8   | suite    | mmap_coherency           | 2/tcp   | ✅ PASS    | 1/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
9   | suite    | zero_silent_loss         | 2/tcp   | ✅ PASS    | 1/60s     | nodes_pass=2/2 checks=44 passed=44 failed=0
10  | suite    | dlm_fairness             | 2/tcp   | ✅ PASS    | 2/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 2/tcp   | ✅ PASS    | 5/30s     | nodes_pass=2/2 checks=6 passed=6 failed=0
12  | suite    | scaling_curve            | 2/tcp   | ✅ PASS    | 2/90s     | nodes_pass=2/2 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 2/tcp   | ✅ PASS    | 10/90s    | nodes_pass=2/2 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 2/tcp   | ✅ PASS    | 4/60s     | nodes_pass=2/2 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 2/tcp   | ✅ PASS    | 5/90s     | nodes_pass=2/2 checks=104 passed=104 failed=0
16  | suite    | dir_reuse_coherency      | 2/tcp   | ✅ PASS    | 101/120s  | nodes_pass=2/2 checks=163 passed=163 failed=0
17  | suite    | fence_during_write       | 2/tcp   | ✅ PASS    | 16/60s    | nodes_pass=2/2 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 2/tcp   | ✅ PASS    | 7/60s     | nodes_pass=2/2 checks=5 passed=5 failed=0
19  | suite    | soak                     | 2/tcp   | ✅ PASS    | 31/60s    | dur=30s ops=1525 errs=0 dmesg_hits=0
20  | tcp      | tcp_dlm_scaling          | 2/tcp   | ✅ PASS    | 17/300s   | nodes_pass=2/2 checks=7 passed=7 failed=0
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=2 dlm=tcp]

=== MXFS TEST STATUS — conditions — nodes=4 dlm=tcp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 4/tcp   | ✅ PASS    | 0/300s    | skipped (marker matched 4/tcp)
2   | suite    | precond_readiness        | 4/tcp   | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 4/tcp   | ✅ PASS    | 88/120s   | nodes_pass=4/4 seqW=1616MiB/s seqR=30328MiB/s randW=1022iops randR=344833iops
4   | suite    | fio_perf_vs_xfs          | 4/tcp   | ✅ PASS    | 0/10s     | seqW=376% seqR=257% randW=90% randR=318% worst(write)=90% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 4/tcp   | ✅ PASS    | 6/60s     | nodes_pass=4/4 checks=542 passed=542 failed=0
6   | suite    | strong_consistency       | 4/tcp   | ✅ PASS    | 1/30s     | nodes_pass=4/4 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 4/tcp   | ✅ PASS    | 2/30s     | nodes_pass=4/4 checks=80 passed=80 failed=0
8   | suite    | mmap_coherency           | 4/tcp   | ✅ PASS    | 1/30s     | nodes_pass=4/4 checks=7 passed=7 failed=0
9   | suite    | zero_silent_loss         | 4/tcp   | ✅ PASS    | 2/60s     | nodes_pass=4/4 checks=84 passed=84 failed=0
10  | suite    | dlm_fairness             | 4/tcp   | ✅ PASS    | 4/30s     | nodes_pass=4/4 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 4/tcp   | ✅ PASS    | 5/30s     | nodes_pass=4/4 checks=6 passed=6 failed=0
12  | suite    | scaling_curve            | 4/tcp   | ✅ PASS    | 3/90s     | nodes_pass=4/4 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 4/tcp   | ✅ PASS    | 12/90s    | nodes_pass=4/4 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 4/tcp   | ✅ PASS    | 4/60s     | nodes_pass=4/4 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 4/tcp   | ✅ PASS    | 7/90s     | nodes_pass=4/4 checks=204 passed=204 failed=0
16  | suite    | dir_reuse_coherency      | 4/tcp   | ✅ PASS    | 104/120s  | nodes_pass=4/4 checks=156 passed=156 failed=0
17  | suite    | fence_during_write       | 4/tcp   | ✅ PASS    | 16/60s    | nodes_pass=4/4 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 4/tcp   | ✅ PASS    | 8/60s     | nodes_pass=4/4 checks=5 passed=5 failed=0
19  | suite    | soak                     | 4/tcp   | ✅ PASS    | 32/60s    | dur=30s ops=1608 errs=0 dmesg_hits=0
20  | tcp      | tcp_dlm_scaling          | 4/tcp   | ✅ PASS    | 21/300s   | nodes_pass=4/4 checks=7 passed=7 failed=0
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=4 dlm=tcp]

=== MXFS TEST STATUS — conditions — nodes=8 dlm=tcp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 8/tcp   | ✅ PASS    | 0/300s    | skipped (marker matched 8/tcp)
2   | suite    | precond_readiness        | 8/tcp   | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 8/tcp   | ✅ PASS    | 88/120s   | nodes_pass=8/8 seqW=638MiB/s seqR=38674MiB/s randW=1196iops randR=489231iops
4   | suite    | fio_perf_vs_xfs          | 8/tcp   | ✅ PASS    | 0/10s     | seqW=205% seqR=298% randW=78% randR=459% worst(write)=78% (threshold>=70%, wsrc=xfs-baseline)
5   | suite    | cache_coherency          | 8/tcp   | ✅ PASS    | 8/60s     | nodes_pass=8/8 checks=558 passed=558 failed=0
6   | suite    | strong_consistency       | 8/tcp   | ✅ PASS    | 1/30s     | nodes_pass=8/8 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 8/tcp   | ✅ PASS    | 2/30s     | nodes_pass=8/8 checks=56 passed=56 failed=0
8   | suite    | mmap_coherency           | 8/tcp   | ✅ PASS    | 1/30s     | nodes_pass=8/8 checks=11 passed=11 failed=0
9   | suite    | zero_silent_loss         | 8/tcp   | ✅ PASS    | 3/60s     | nodes_pass=8/8 checks=164 passed=164 failed=0
10  | suite    | dlm_fairness             | 8/tcp   | ✅ PASS    | 8/30s     | nodes_pass=8/8 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 8/tcp   | ✅ PASS    | 4/30s     | nodes_pass=8/8 checks=6 passed=6 failed=0
12  | suite    | scaling_curve            | 8/tcp   | ✅ PASS    | 4/90s     | nodes_pass=8/8 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 8/tcp   | ✅ PASS    | 14/90s    | nodes_pass=8/8 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 8/tcp   | ✅ PASS    | 5/60s     | nodes_pass=8/8 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 8/tcp   | ✅ PASS    | 16/90s    | nodes_pass=8/8 checks=404 passed=404 failed=0
16  | suite    | dir_reuse_coherency      | 8/tcp   | ✅ PASS    | 103/120s  | nodes_pass=8/8 checks=128 passed=128 failed=0
17  | suite    | fence_during_write       | 8/tcp   | ✅ PASS    | 17/60s    | nodes_pass=8/8 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 8/tcp   | ✅ PASS    | 8/60s     | nodes_pass=8/8 checks=5 passed=5 failed=0
19  | suite    | soak                     | 8/tcp   | ✅ PASS    | 32/60s    | dur=30s ops=1615 errs=0 dmesg_hits=0
20  | tcp      | tcp_dlm_scaling          | 8/tcp   | ✅ PASS    | 27/300s   | nodes_pass=8/8 checks=7 passed=7 failed=0
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=8 dlm=tcp]

=== MXFS TEST STATUS — conditions — nodes=16 dlm=tcp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 16/tcp  | ✅ PASS    | 0/300s    | skipped (marker matched 16/tcp)
2   | suite    | precond_readiness        | 16/tcp  | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 16/tcp  | ✅ PASS    | 86/120s   | nodes_pass=16/16 seqW=1654MiB/s seqR=52406MiB/s randW=948iops randR=954998iops
4   | suite    | fio_perf_vs_xfs          | 16/tcp  | ✅ PASS    | 1/10s     | seqW=653% seqR=475% randW=113% randR=862% worst(write)=113% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 16/tcp  | ✅ PASS    | 13/60s    | nodes_pass=16/16 checks=590 passed=590 failed=0
6   | suite    | strong_consistency       | 16/tcp  | ✅ PASS    | 3/30s     | nodes_pass=16/16 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 16/tcp  | ✅ PASS    | 4/30s     | nodes_pass=16/16 checks=56 passed=56 failed=0
8   | suite    | mmap_coherency           | 16/tcp  | ✅ PASS    | 2/30s     | nodes_pass=16/16 checks=19 passed=19 failed=0
9   | suite    | zero_silent_loss         | 16/tcp  | ✅ PASS    | 6/60s     | nodes_pass=16/16 checks=324 passed=324 failed=0
10  | suite    | dlm_fairness             | 16/tcp  | ✅ PASS    | 11/30s    | nodes_pass=16/16 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 16/tcp  | ✅ PASS    | 4/30s     | nodes_pass=16/16 checks=6 passed=6 failed=0
12  | suite    | scaling_curve            | 16/tcp  | ✅ PASS    | 7/90s     | nodes_pass=16/16 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 16/tcp  | ✅ PASS    | 24/90s    | nodes_pass=16/16 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 16/tcp  | ✅ PASS    | 9/60s     | nodes_pass=16/16 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 16/tcp  | ✅ PASS    | 33/90s    | nodes_pass=16/16 checks=354 passed=354 failed=0
16  | suite    | dir_reuse_coherency      | 16/tcp  | ✅ PASS    | 106/120s  | nodes_pass=16/16 checks=107 passed=107 failed=0
17  | suite    | fence_during_write       | 16/tcp  | ✅ PASS    | 19/60s    | nodes_pass=16/16 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 16/tcp  | ✅ PASS    | 9/60s     | nodes_pass=16/16 checks=5 passed=5 failed=0
19  | suite    | soak                     | 16/tcp  | ✅ PASS    | 32/60s    | dur=30s ops=1453 errs=0 dmesg_hits=0
20  | tcp      | tcp_dlm_scaling          | 16/tcp  | ✅ PASS    | 34/300s   | nodes_pass=16/16 checks=7 passed=7 failed=0
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=16 dlm=tcp]

=== MXFS TEST STATUS — conditions — nodes=32 dlm=tcp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 32/tcp  | ✅ PASS    | 0/300s    | skipped (marker matched 32/tcp)
2   | suite    | precond_readiness        | 32/tcp  | ✅ PASS    | 2/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 32/tcp  | ✅ PASS    | 103/120s  | nodes_pass=32/32 seqW=4224MiB/s seqR=46087MiB/s randW=959iops randR=1723398iops
4   | suite    | fio_perf_vs_xfs          | 32/tcp  | ✅ PASS    | 1/10s     | seqW=505% seqR=378% randW=71% randR=1535% worst(write)=71% (threshold>=70%, wsrc=xfs-baseline)
5   | suite    | cache_coherency          | 32/tcp  | ✅ PASS    | 29/60s    | nodes_pass=32/32 checks=654 passed=654 failed=0
6   | suite    | strong_consistency       | 32/tcp  | ✅ PASS    | 6/30s     | nodes_pass=32/32 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 32/tcp  | ✅ PASS    | 7/30s     | nodes_pass=32/32 checks=80 passed=80 failed=0
8   | suite    | mmap_coherency           | 32/tcp  | ✅ PASS    | 7/30s     | nodes_pass=32/32 checks=35 passed=35 failed=0
9   | suite    | zero_silent_loss         | 32/tcp  | ✅ PASS    | 19/60s    | nodes_pass=32/32 checks=644 passed=644 failed=0
10  | suite    | dlm_fairness             | 32/tcp  | ✅ PASS    | 13/30s    | nodes_pass=32/32 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 32/tcp  | ✅ PASS    | 6/30s     | nodes_pass=32/32 checks=6 passed=6 failed=0
12  | suite    | scaling_curve            | 32/tcp  | ✅ PASS    | 30/90s    | nodes_pass=32/32 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 32/tcp  | ✅ PASS    | 46/90s    | nodes_pass=32/32 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 32/tcp  | ✅ PASS    | 17/60s    | nodes_pass=32/32 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 32/tcp  | ✅ PASS    | 76/90s    | nodes_pass=32/32 checks=204 passed=204 failed=0
16  | suite    | dir_reuse_coherency      | 32/tcp  | ✅ PASS    | 101/120s  | nodes_pass=32/32 checks=72 passed=72 failed=0
17  | suite    | fence_during_write       | 32/tcp  | ✅ PASS    | 19/60s    | nodes_pass=32/32 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 32/tcp  | ✅ PASS    | 13/60s    | nodes_pass=32/32 checks=5 passed=5 failed=0
19  | suite    | soak                     | 32/tcp  | ✅ PASS    | 31/60s    | dur=30s ops=1348 errs=0 dmesg_hits=0
20  | tcp      | tcp_dlm_scaling          | 32/tcp  | ✅ PASS    | 41/300s   | nodes_pass=32/32 checks=7 passed=7 failed=0
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=32 dlm=tcp]



=== MXFS TEST STATUS — conditions — nodes=1 dlm=cawp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 1/cawp  | ✅ PASS    | 0/300s    | skipped (marker matched 1/cawp)
2   | suite    | precond_readiness        | 1/cawp  | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | posix_single             | 1/cawp  | ✅ PASS    | 2/15s     | checks=29 passed=29 failed=0
4   | suite    | fsx                      | 1/cawp  | ✅ PASS    | 9/88s     | checks=2 passed=2 failed=0
5   | suite    | fio_verify               | 1/cawp  | ✅ PASS    | 3/42s     | checks=3 passed=3 failed=0
6   | suite    | integrity_filetypes      | 1/cawp  | ✅ PASS    | 2/10s     | checks=13 passed=13 failed=0
7   | suite    | fio_perf                 | 1/cawp  | ✅ PASS    | 11/120s   | nodes_pass=1/1 seqW=1558MiB/s seqR=1519MiB/s randW=50104iops randR=55072iops
8   | suite    | fio_perf_vs_xfs          | 1/cawp  | ✅ PASS    | 1/10s     | seqW=90% seqR=71% randW=117% randR=106% worst(write)=90% (threshold>=70%, wsrc=xfs-baseline)
9   | suite    | cache_coherency          | 1/cawp  | ✅ PASS    | 1/60s     | nodes_pass=1/1 checks=530 passed=530 failed=0
10  | suite    | strong_consistency       | 1/cawp  | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=7 passed=7 failed=0
11  | suite    | posix_multi              | 1/cawp  | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=266 passed=266 failed=0
12  | suite    | mmap_coherency           | 1/cawp  | ✅ PASS    | 1/30s     | nodes_pass=1/1 checks=4 passed=4 failed=0
13  | suite    | zero_silent_loss         | 1/cawp  | ✅ PASS    | 0/60s     | nodes_pass=1/1 checks=24 passed=24 failed=0
14  | suite    | dlm_fairness             | 1/cawp  | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=5 passed=5 failed=0
15  | suite    | scaling_curve            | 1/cawp  | ✅ PASS    | 0/90s     | nodes_pass=1/1 checks=7 passed=7 failed=0
16  | suite    | dlm_scaling              | 1/cawp  | ✅ PASS    | 8/90s     | nodes_pass=1/1 checks=6 passed=6 failed=0
17  | suite    | rsync_paired             | 1/cawp  | ✅ PASS    | 2/60s     | nodes_pass=1/1 checks=6 passed=6 failed=0
18  | suite    | fault_enospc             | 1/cawp  | ✅ PASS    | 0/10s     | checks=4 passed=4 failed=0
19  | suite    | crash_consistency        | 1/cawp  | ✅ PASS    | 2/90s     | nodes_pass=1/1 checks=54 passed=54 failed=0
20  | suite    | dir_reuse_coherency      | 1/cawp  | ✅ PASS    | 50/120s   | nodes_pass=1/1 checks=170 passed=170 failed=0
21  | suite    | soak                     | 1/cawp  | ✅ PASS    | 31/60s    | dur=30s ops=1929 errs=0 dmesg_hits=0
22  | tooling  | mkfs_timing              | 1/cawp  | ✅ PASS    | 1/10s     | 255ms (threshold<=10000ms)
23  | tooling  | chk_clean                | 1/cawp  | ✅ PASS    | 0/10s     | rc=0 errors=0
24  | tooling  | online_resize            | 1/cawp  | ✅ PASS    | 12/25s    | pre=1695MB post=3743MB delta=2048MB/+2048MB data_intact=yes
25  | tooling  | dkms_install             | 1/cawp  | ✅ PASS    | 88/240s   | add=0 build=0 install=0 installed=yes remove=0 clean=yes
26  | tooling  | single_node_paired       | 1/cawp  | ✅ PASS    | 33/90s    | xfs=(3195/2668/2714/2653)ms mxfs=(2640/2707/2664/2650)ms round_ratios=82,98,99,101 ratio=98% files=8714/8714
27  | tooling  | fio_vs_xfs_baseline      | 1/cawp  | ✅ PASS    | 135/180s  | seqW=353/613MiB rounds=124,57,110,87→98% randW=38058/26301iops rounds=118,144,130,160→137% worst_write=98% [reads cache-bound: seqR 120% randR 94%]
28  | tooling  | cluster_ops_timing       | 1/cawp  | ✅ PASS    | 2/10s     | first=91ms rest=100ms umount=440ms
29  | tooling  | fault_io_error           | 1/cawp  | ✅ PASS    | 2/60s     | nodes_pass=1/1 eio=yes wms=5 bad_dmesg=0 remount=yes data_intact=yes chk_rc=0
30  | caw      | dlm_lock_correctness     | 1/cawp  | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 30 — 30 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=1 dlm=cawp]

=== MXFS TEST STATUS — conditions — nodes=2 dlm=cawp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 2/cawp  | ✅ PASS    | 0/300s    | skipped (marker matched 2/cawp)
2   | suite    | precond_readiness        | 2/cawp  | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 2/cawp  | ✅ PASS    | 11/120s   | nodes_pass=2/2 seqW=1817MiB/s seqR=3034MiB/s randW=61944iops randR=88585iops
4   | suite    | fio_perf_vs_xfs          | 2/cawp  | ✅ PASS    | 0/10s     | seqW=553% seqR=168% randW=92% randR=175% worst(write)=92% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 2/cawp  | ✅ PASS    | 5/60s     | nodes_pass=2/2 checks=534 passed=534 failed=0
6   | suite    | strong_consistency       | 2/cawp  | ✅ PASS    | 1/30s     | nodes_pass=2/2 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 2/cawp  | ✅ PASS    | 2/30s     | nodes_pass=2/2 checks=140 passed=140 failed=0
8   | suite    | mmap_coherency           | 2/cawp  | ✅ PASS    | 1/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
9   | suite    | zero_silent_loss         | 2/cawp  | ✅ PASS    | 1/60s     | nodes_pass=2/2 checks=44 passed=44 failed=0
10  | suite    | dlm_fairness             | 2/cawp  | ✅ PASS    | 3/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 2/cawp  | ✅ PASS    | 3/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 2/cawp  | ✅ PASS    | 1/90s     | nodes_pass=2/2 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 2/cawp  | ✅ PASS    | 12/90s    | nodes_pass=2/2 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 2/cawp  | ✅ PASS    | 5/60s     | nodes_pass=2/2 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 2/cawp  | ✅ PASS    | 5/90s     | nodes_pass=2/2 checks=104 passed=104 failed=0
16  | suite    | dir_reuse_coherency      | 2/cawp  | ✅ PASS    | 101/120s  | nodes_pass=2/2 checks=163 passed=163 failed=0
17  | suite    | fence_during_write       | 2/cawp  | ✅ PASS    | 17/60s    | nodes_pass=2/2 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 2/cawp  | ✅ PASS    | 6/60s     | nodes_pass=2/2 checks=5 passed=5 failed=0
19  | suite    | soak                     | 2/cawp  | ✅ PASS    | 31/60s    | dur=30s ops=1296 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 2/cawp  | ✅ PASS    | 1/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=2 dlm=cawp]

=== MXFS TEST STATUS — conditions — nodes=4 dlm=cawp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 4/cawp  | ✅ PASS    | 0/300s    | skipped (marker matched 4/cawp)
2   | suite    | precond_readiness        | 4/cawp  | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 4/cawp  | ✅ PASS    | 20/120s   | nodes_pass=4/4 seqW=812MiB/s seqR=3766MiB/s randW=78123iops randR=136871iops
4   | suite    | fio_perf_vs_xfs          | 4/cawp  | ✅ PASS    | 0/10s     | seqW=221% seqR=224% randW=107% randR=309% worst(write)=107% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 4/cawp  | ✅ PASS    | 5/60s     | nodes_pass=4/4 checks=542 passed=542 failed=0
6   | suite    | strong_consistency       | 4/cawp  | ✅ PASS    | 1/30s     | nodes_pass=4/4 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 4/cawp  | ✅ PASS    | 2/30s     | nodes_pass=4/4 checks=80 passed=80 failed=0
8   | suite    | mmap_coherency           | 4/cawp  | ✅ PASS    | 1/30s     | nodes_pass=4/4 checks=7 passed=7 failed=0
9   | suite    | zero_silent_loss         | 4/cawp  | ✅ PASS    | 2/60s     | nodes_pass=4/4 checks=84 passed=84 failed=0
10  | suite    | dlm_fairness             | 4/cawp  | ✅ PASS    | 6/30s     | nodes_pass=4/4 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 4/cawp  | ✅ PASS    | 3/30s     | nodes_pass=4/4 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 4/cawp  | ✅ PASS    | 1/90s     | nodes_pass=4/4 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 4/cawp  | ✅ PASS    | 12/90s    | nodes_pass=4/4 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 4/cawp  | ✅ PASS    | 6/60s     | nodes_pass=4/4 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 4/cawp  | ✅ PASS    | 8/90s     | nodes_pass=4/4 checks=204 passed=204 failed=0
16  | suite    | dir_reuse_coherency      | 4/cawp  | ✅ PASS    | 105/120s  | nodes_pass=4/4 checks=156 passed=156 failed=0
17  | suite    | fence_during_write       | 4/cawp  | ✅ PASS    | 17/60s    | nodes_pass=4/4 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 4/cawp  | ✅ PASS    | 7/60s     | nodes_pass=4/4 checks=5 passed=5 failed=0
19  | suite    | soak                     | 4/cawp  | ✅ PASS    | 31/60s    | dur=30s ops=1304 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 4/cawp  | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=4 dlm=cawp]

=== MXFS TEST STATUS — conditions — nodes=8 dlm=cawp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 8/cawp  | ✅ PASS    | 0/300s    | skipped (marker matched 8/cawp)
2   | suite    | precond_readiness        | 8/cawp  | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 8/cawp  | ✅ PASS    | 18/120s   | nodes_pass=8/8 seqW=2115MiB/s seqR=3297MiB/s randW=133280iops randR=285007iops
4   | suite    | fio_perf_vs_xfs          | 8/cawp  | ✅ PASS    | 1/10s     | seqW=716% seqR=200% randW=86% randR=652% worst(write)=86% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 8/cawp  | ✅ PASS    | 8/60s     | nodes_pass=8/8 checks=558 passed=558 failed=0
6   | suite    | strong_consistency       | 8/cawp  | ✅ PASS    | 10/30s    | nodes_pass=8/8 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 8/cawp  | ✅ PASS    | 3/30s     | nodes_pass=8/8 checks=56 passed=56 failed=0
8   | suite    | mmap_coherency           | 8/cawp  | ✅ PASS    | 2/30s     | nodes_pass=8/8 checks=11 passed=11 failed=0
9   | suite    | zero_silent_loss         | 8/cawp  | ✅ PASS    | 4/60s     | nodes_pass=8/8 checks=164 passed=164 failed=0
10  | suite    | dlm_fairness             | 8/cawp  | ✅ PASS    | 9/30s     | nodes_pass=8/8 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 8/cawp  | ✅ PASS    | 3/30s     | nodes_pass=8/8 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 8/cawp  | ✅ PASS    | 3/90s     | nodes_pass=8/8 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 8/cawp  | ✅ PASS    | 16/90s    | nodes_pass=8/8 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 8/cawp  | ✅ PASS    | 15/60s    | nodes_pass=8/8 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 8/cawp  | ✅ PASS    | 15/90s    | nodes_pass=8/8 checks=404 passed=404 failed=0
16  | suite    | dir_reuse_coherency      | 8/cawp  | ✅ PASS    | 106/120s  | nodes_pass=8/8 checks=114 passed=114 failed=0
17  | suite    | fence_during_write       | 8/cawp  | ✅ PASS    | 17/60s    | nodes_pass=8/8 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 8/cawp  | ✅ PASS    | 7/60s     | nodes_pass=8/8 checks=5 passed=5 failed=0
19  | suite    | soak                     | 8/cawp  | ✅ PASS    | 31/60s    | dur=30s ops=1261 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 8/cawp  | ✅ PASS    | 1/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=8 dlm=cawp]

=== MXFS TEST STATUS — conditions — nodes=16 dlm=cawp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 16/cawp | ✅ PASS    | 0/300s    | skipped (marker matched 16/cawp)
2   | suite    | precond_readiness        | 16/cawp | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 16/cawp | ✅ PASS    | 30/120s   | nodes_pass=16/16 seqW=556MiB/s seqR=2031MiB/s randW=308887iops randR=516061iops
4   | suite    | fio_perf_vs_xfs          | 16/cawp | ✅ PASS    | 1/10s     | seqW=92% seqR=122% randW=139% randR=1069% worst(write)=92% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 16/cawp | ✅ PASS    | 13/60s    | nodes_pass=16/16 checks=590 passed=590 failed=0
6   | suite    | strong_consistency       | 16/cawp | ✅ PASS    | 3/30s     | nodes_pass=16/16 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 16/cawp | ✅ PASS    | 4/30s     | nodes_pass=16/16 checks=56 passed=56 failed=0
8   | suite    | mmap_coherency           | 16/cawp | ✅ PASS    | 3/30s     | nodes_pass=16/16 checks=19 passed=19 failed=0
9   | suite    | zero_silent_loss         | 16/cawp | ✅ PASS    | 9/60s     | nodes_pass=16/16 checks=324 passed=324 failed=0
10  | suite    | dlm_fairness             | 16/cawp | ✅ PASS    | 14/30s    | nodes_pass=16/16 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 16/cawp | ✅ PASS    | 4/30s     | nodes_pass=16/16 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 16/cawp | ✅ PASS    | 4/90s     | nodes_pass=16/16 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 16/cawp | ✅ PASS    | 22/90s    | nodes_pass=16/16 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 16/cawp | ✅ PASS    | 18/60s    | nodes_pass=16/16 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 16/cawp | ✅ PASS    | 26/90s    | nodes_pass=16/16 checks=354 passed=354 failed=0
16  | suite    | dir_reuse_coherency      | 16/cawp | ✅ PASS    | 102/120s  | nodes_pass=16/16 checks=86 passed=86 failed=0
17  | suite    | fence_during_write       | 16/cawp | ✅ PASS    | 18/60s    | nodes_pass=16/16 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 16/cawp | ✅ PASS    | 7/60s     | nodes_pass=16/16 checks=5 passed=5 failed=0
19  | suite    | soak                     | 16/cawp | ✅ PASS    | 32/60s    | dur=30s ops=1182 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 16/cawp | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=16 dlm=cawp]

=== MXFS TEST STATUS — conditions — nodes=32 dlm=cawp ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 32/cawp | ✅ PASS    | 0/300s    | skipped (marker matched 32/cawp)
2   | suite    | precond_readiness        | 32/cawp | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 32/cawp | ✅ PASS    | 25/120s   | nodes_pass=32/32 seqW=11345MiB/s seqR=9867MiB/s randW=268931iops randR=508343iops
4   | suite    | fio_perf_vs_xfs          | 32/cawp | ✅ PASS    | 0/10s     | seqW=3427% seqR=600% randW=91% randR=1089% worst(write)=91% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 32/cawp | ✅ PASS    | 26/60s    | nodes_pass=32/32 checks=654 passed=654 failed=0
6   | suite    | strong_consistency       | 32/cawp | ✅ PASS    | 5/30s     | nodes_pass=32/32 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 32/cawp | ✅ PASS    | 7/30s     | nodes_pass=32/32 checks=80 passed=80 failed=0
8   | suite    | mmap_coherency           | 32/cawp | ✅ PASS    | 8/30s     | nodes_pass=32/32 checks=35 passed=35 failed=0
9   | suite    | zero_silent_loss         | 32/cawp | ✅ PASS    | 25/60s    | nodes_pass=32/32 checks=644 passed=644 failed=0
10  | suite    | dlm_fairness             | 32/cawp | ✅ PASS    | 16/30s    | nodes_pass=32/32 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 32/cawp | ✅ PASS    | 6/30s     | nodes_pass=32/32 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 32/cawp | ✅ PASS    | 24/90s    | nodes_pass=32/32 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 32/cawp | ✅ PASS    | 34/90s    | nodes_pass=32/32 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 32/cawp | ✅ PASS    | 24/60s    | nodes_pass=32/32 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 32/cawp | ✅ PASS    | 61/90s    | nodes_pass=32/32 checks=204 passed=204 failed=0
16  | suite    | dir_reuse_coherency      | 32/cawp | ✅ PASS    | 104/120s  | nodes_pass=32/32 checks=58 passed=58 failed=0
17  | suite    | fence_during_write       | 32/cawp | ✅ PASS    | 20/60s    | nodes_pass=32/32 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 32/cawp | ✅ PASS    | 14/60s    | nodes_pass=32/32 checks=5 passed=5 failed=0
19  | suite    | soak                     | 32/cawp | ✅ PASS    | 31/60s    | dur=30s ops=1117 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 32/cawp | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=32 dlm=cawp]



=== MXFS TEST STATUS — conditions — nodes=1 dlm=cawd ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 1/cawd  | ✅ PASS    | 0/300s    | skipped (marker matched 1/cawd)
2   | suite    | precond_readiness        | 1/cawd  | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | posix_single             | 1/cawd  | ✅ PASS    | 2/15s     | checks=29 passed=29 failed=0
4   | suite    | fsx                      | 1/cawd  | ✅ PASS    | 10/88s    | checks=2 passed=2 failed=0
5   | suite    | fio_verify               | 1/cawd  | ✅ PASS    | 3/42s     | checks=3 passed=3 failed=0
6   | suite    | integrity_filetypes      | 1/cawd  | ✅ PASS    | 2/10s     | checks=13 passed=13 failed=0
7   | suite    | fio_perf                 | 1/cawd  | ✅ PASS    | 12/120s   | nodes_pass=1/1 seqW=1969MiB/s seqR=518MiB/s randW=51040iops randR=50568iops
8   | suite    | fio_perf_vs_xfs          | 1/cawd  | ✅ PASS    | 0/10s     | seqW=130% seqR=86% randW=107% randR=113% worst(write)=107% (threshold>=70%, wsrc=xfs-baseline)
9   | suite    | cache_coherency          | 1/cawd  | ✅ PASS    | 1/60s     | nodes_pass=1/1 checks=530 passed=530 failed=0
10  | suite    | strong_consistency       | 1/cawd  | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=7 passed=7 failed=0
11  | suite    | posix_multi              | 1/cawd  | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=266 passed=266 failed=0
12  | suite    | mmap_coherency           | 1/cawd  | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=4 passed=4 failed=0
13  | suite    | zero_silent_loss         | 1/cawd  | ✅ PASS    | 0/60s     | nodes_pass=1/1 checks=24 passed=24 failed=0
14  | suite    | dlm_fairness             | 1/cawd  | ✅ PASS    | 1/30s     | nodes_pass=1/1 checks=5 passed=5 failed=0
15  | suite    | scaling_curve            | 1/cawd  | ✅ PASS    | 1/90s     | nodes_pass=1/1 checks=7 passed=7 failed=0
16  | suite    | dlm_scaling              | 1/cawd  | ✅ PASS    | 10/90s    | nodes_pass=1/1 checks=6 passed=6 failed=0
17  | suite    | rsync_paired             | 1/cawd  | ✅ PASS    | 3/60s     | nodes_pass=1/1 checks=6 passed=6 failed=0
18  | suite    | fault_enospc             | 1/cawd  | ✅ PASS    | 1/10s     | checks=4 passed=4 failed=0
19  | suite    | crash_consistency        | 1/cawd  | ✅ PASS    | 2/90s     | nodes_pass=1/1 checks=54 passed=54 failed=0
20  | suite    | dir_reuse_coherency      | 1/cawd  | ✅ PASS    | 51/120s   | nodes_pass=1/1 checks=170 passed=170 failed=0
21  | suite    | soak                     | 1/cawd  | ✅ PASS    | 30/60s    | dur=30s ops=1627 errs=0 dmesg_hits=0
22  | tooling  | mkfs_timing              | 1/cawd  | ✅ PASS    | 1/10s     | 232ms (threshold<=10000ms)
23  | tooling  | chk_clean                | 1/cawd  | ✅ PASS    | 0/10s     | rc=0 errors=0
24  | tooling  | online_resize            | 1/cawd  | ✅ PASS    | 13/25s    | pre=1695MB post=3743MB delta=2048MB/+2048MB data_intact=yes
25  | tooling  | dkms_install             | 1/cawd  | ✅ PASS    | 91/240s   | add=0 build=0 install=0 installed=yes remove=0 clean=yes
26  | tooling  | single_node_paired       | 1/cawd  | ✅ PASS    | 36/90s    | xfs=(2632/2694/2922/2855)ms mxfs=(2805/2823/2822/3303)ms round_ratios=96,104,106,115 ratio=105% files=8714/8714
27  | tooling  | fio_vs_xfs_baseline      | 1/cawd  | ✅ PASS    | 133/180s  | seqW=390/191MiB rounds=100,204,133,51→116% randW=10429/10725iops rounds=134,97,122,145→128% worst_write=116% [reads cache-bound: seqR 89% randR 98%]
28  | tooling  | cluster_ops_timing       | 1/cawd  | ✅ PASS    | 2/10s     | first=403ms rest=401ms umount=112ms
29  | tooling  | fault_io_error           | 1/cawd  | ✅ PASS    | 3/60s     | nodes_pass=1/1 eio=yes wms=5 bad_dmesg=0 remount=yes data_intact=yes chk_rc=0
30  | caw      | dlm_lock_correctness     | 1/cawd  | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 30 — 30 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=1 dlm=cawd]

=== MXFS TEST STATUS — conditions — nodes=2 dlm=cawd ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 2/cawd  | ✅ PASS    | 0/300s    | skipped (marker matched 2/cawd)
2   | suite    | precond_readiness        | 2/cawd  | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 2/cawd  | ✅ PASS    | 13/120s   | nodes_pass=2/2 seqW=2585MiB/s seqR=1640MiB/s randW=85058iops randR=80387iops
4   | suite    | fio_perf_vs_xfs          | 2/cawd  | ✅ PASS    | 1/10s     | seqW=578% seqR=299% randW=104% randR=198% worst(write)=104% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 2/cawd  | ✅ PASS    | 5/60s     | nodes_pass=2/2 checks=534 passed=534 failed=0
6   | suite    | strong_consistency       | 2/cawd  | ✅ PASS    | 1/30s     | nodes_pass=2/2 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 2/cawd  | ✅ PASS    | 1/30s     | nodes_pass=2/2 checks=140 passed=140 failed=0
8   | suite    | mmap_coherency           | 2/cawd  | ✅ PASS    | 1/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
9   | suite    | zero_silent_loss         | 2/cawd  | ✅ PASS    | 2/60s     | nodes_pass=2/2 checks=44 passed=44 failed=0
10  | suite    | dlm_fairness             | 2/cawd  | ✅ PASS    | 3/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 2/cawd  | ✅ PASS    | 3/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 2/cawd  | ✅ PASS    | 1/90s     | nodes_pass=2/2 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 2/cawd  | ✅ PASS    | 11/90s    | nodes_pass=2/2 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 2/cawd  | ✅ PASS    | 4/60s     | nodes_pass=2/2 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 2/cawd  | ✅ PASS    | 5/90s     | nodes_pass=2/2 checks=104 passed=104 failed=0
16  | suite    | dir_reuse_coherency      | 2/cawd  | ✅ PASS    | 102/120s  | nodes_pass=2/2 checks=170 passed=170 failed=0
17  | suite    | fence_during_write       | 2/cawd  | ✅ PASS    | 17/60s    | nodes_pass=2/2 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 2/cawd  | ✅ PASS    | 7/60s     | nodes_pass=2/2 checks=5 passed=5 failed=0
19  | suite    | soak                     | 2/cawd  | ✅ PASS    | 31/60s    | dur=30s ops=1356 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 2/cawd  | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=2 dlm=cawd]

=== MXFS TEST STATUS — conditions — nodes=4 dlm=cawd ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 4/cawd  | ✅ PASS    | 0/300s    | skipped (marker matched 4/cawd)
2   | suite    | precond_readiness        | 4/cawd  | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 4/cawd  | ✅ PASS    | 12/120s   | nodes_pass=4/4 seqW=2516MiB/s seqR=2296MiB/s randW=141543iops randR=143696iops
4   | suite    | fio_perf_vs_xfs          | 4/cawd  | ✅ PASS    | 0/10s     | seqW=762% seqR=386% randW=106% randR=422% worst(write)=106% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 4/cawd  | ✅ PASS    | 5/60s     | nodes_pass=4/4 checks=542 passed=542 failed=0
6   | suite    | strong_consistency       | 4/cawd  | ✅ PASS    | 1/30s     | nodes_pass=4/4 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 4/cawd  | ✅ PASS    | 2/30s     | nodes_pass=4/4 checks=80 passed=80 failed=0
8   | suite    | mmap_coherency           | 4/cawd  | ✅ PASS    | 1/30s     | nodes_pass=4/4 checks=7 passed=7 failed=0
9   | suite    | zero_silent_loss         | 4/cawd  | ✅ PASS    | 2/60s     | nodes_pass=4/4 checks=84 passed=84 failed=0
10  | suite    | dlm_fairness             | 4/cawd  | ✅ PASS    | 5/30s     | nodes_pass=4/4 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 4/cawd  | ✅ PASS    | 3/30s     | nodes_pass=4/4 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 4/cawd  | ✅ PASS    | 1/90s     | nodes_pass=4/4 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 4/cawd  | ✅ PASS    | 12/90s    | nodes_pass=4/4 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 4/cawd  | ✅ PASS    | 13/60s    | nodes_pass=4/4 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 4/cawd  | ✅ PASS    | 7/90s     | nodes_pass=4/4 checks=204 passed=204 failed=0
16  | suite    | dir_reuse_coherency      | 4/cawd  | ✅ PASS    | 101/120s  | nodes_pass=4/4 checks=149 passed=149 failed=0
17  | suite    | fence_during_write       | 4/cawd  | ✅ PASS    | 17/60s    | nodes_pass=4/4 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 4/cawd  | ✅ PASS    | 6/60s     | nodes_pass=4/4 checks=5 passed=5 failed=0
19  | suite    | soak                     | 4/cawd  | ✅ PASS    | 31/60s    | dur=30s ops=1342 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 4/cawd  | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=4 dlm=cawd]

=== MXFS TEST STATUS — conditions — nodes=8 dlm=cawd ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 8/cawd  | ✅ PASS    | 0/300s    | skipped (marker matched 8/cawd)
2   | suite    | precond_readiness        | 8/cawd  | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 8/cawd  | ✅ PASS    | 15/120s   | nodes_pass=8/8 seqW=1665MiB/s seqR=3917MiB/s randW=203622iops randR=238078iops
4   | suite    | fio_perf_vs_xfs          | 8/cawd  | ✅ PASS    | 0/10s     | seqW=232% seqR=671% randW=158% randR=536% worst(write)=158% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 8/cawd  | ✅ PASS    | 8/60s     | nodes_pass=8/8 checks=558 passed=558 failed=0
6   | suite    | strong_consistency       | 8/cawd  | ✅ PASS    | 2/30s     | nodes_pass=8/8 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 8/cawd  | ✅ PASS    | 3/30s     | nodes_pass=8/8 checks=56 passed=56 failed=0
8   | suite    | mmap_coherency           | 8/cawd  | ✅ PASS    | 2/30s     | nodes_pass=8/8 checks=11 passed=11 failed=0
9   | suite    | zero_silent_loss         | 8/cawd  | ✅ PASS    | 3/60s     | nodes_pass=8/8 checks=164 passed=164 failed=0
10  | suite    | dlm_fairness             | 8/cawd  | ✅ PASS    | 9/30s     | nodes_pass=8/8 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 8/cawd  | ✅ PASS    | 3/30s     | nodes_pass=8/8 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 8/cawd  | ✅ PASS    | 2/90s     | nodes_pass=8/8 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 8/cawd  | ✅ PASS    | 14/90s    | nodes_pass=8/8 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 8/cawd  | ✅ PASS    | 14/60s    | nodes_pass=8/8 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 8/cawd  | ✅ PASS    | 14/90s    | nodes_pass=8/8 checks=404 passed=404 failed=0
16  | suite    | dir_reuse_coherency      | 8/cawd  | ✅ PASS    | 101/120s  | nodes_pass=8/8 checks=121 passed=121 failed=0
17  | suite    | fence_during_write       | 8/cawd  | ✅ PASS    | 17/60s    | nodes_pass=8/8 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 8/cawd  | ✅ PASS    | 7/60s     | nodes_pass=8/8 checks=5 passed=5 failed=0
19  | suite    | soak                     | 8/cawd  | ✅ PASS    | 31/60s    | dur=30s ops=1362 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 8/cawd  | ✅ PASS    | 1/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=8 dlm=cawd]

=== MXFS TEST STATUS — conditions — nodes=16 dlm=cawd ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 16/cawd | ✅ PASS    | 0/300s    | skipped (marker matched 16/cawd)
2   | suite    | precond_readiness        | 16/cawd | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 16/cawd | ✅ PASS    | 18/120s   | nodes_pass=16/16 seqW=4371MiB/s seqR=2443MiB/s randW=332733iops randR=273053iops
4   | suite    | fio_perf_vs_xfs          | 16/cawd | ✅ PASS    | 1/10s     | seqW=1900% seqR=441% randW=339% randR=807% worst(write)=339% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 16/cawd | ✅ PASS    | 12/60s    | nodes_pass=16/16 checks=590 passed=590 failed=0
6   | suite    | strong_consistency       | 16/cawd | ✅ PASS    | 3/30s     | nodes_pass=16/16 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 16/cawd | ✅ PASS    | 3/30s     | nodes_pass=16/16 checks=56 passed=56 failed=0
8   | suite    | mmap_coherency           | 16/cawd | ✅ PASS    | 2/30s     | nodes_pass=16/16 checks=19 passed=19 failed=0
9   | suite    | zero_silent_loss         | 16/cawd | ✅ PASS    | 9/60s     | nodes_pass=16/16 checks=324 passed=324 failed=0
10  | suite    | dlm_fairness             | 16/cawd | ✅ PASS    | 12/30s    | nodes_pass=16/16 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 16/cawd | ✅ PASS    | 4/30s     | nodes_pass=16/16 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 16/cawd | ✅ PASS    | 4/90s     | nodes_pass=16/16 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 16/cawd | ✅ PASS    | 19/90s    | nodes_pass=16/16 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 16/cawd | ✅ PASS    | 22/60s    | nodes_pass=16/16 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 16/cawd | ✅ PASS    | 25/90s    | nodes_pass=16/16 checks=354 passed=354 failed=0
16  | suite    | dir_reuse_coherency      | 16/cawd | ✅ PASS    | 106/120s  | nodes_pass=16/16 checks=100 passed=100 failed=0
17  | suite    | fence_during_write       | 16/cawd | ✅ PASS    | 18/60s    | nodes_pass=16/16 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 16/cawd | ✅ PASS    | 8/60s     | nodes_pass=16/16 checks=5 passed=5 failed=0
19  | suite    | soak                     | 16/cawd | ✅ PASS    | 31/60s    | dur=30s ops=1233 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 16/cawd | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=16 dlm=cawd]

=== MXFS TEST STATUS — conditions — nodes=32 dlm=cawd ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 32/cawd | ✅ PASS    | 0/300s    | skipped (marker matched 32/cawd)
2   | suite    | precond_readiness        | 32/cawd | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 32/cawd | ✅ PASS    | 27/120s   | nodes_pass=32/32 seqW=5459MiB/s seqR=7296MiB/s randW=575476iops randR=489109iops
4   | suite    | fio_perf_vs_xfs          | 32/cawd | ✅ PASS    | 1/10s     | seqW=507% seqR=1203% randW=211% randR=1010% worst(write)=211% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 32/cawd | ✅ PASS    | 25/60s    | nodes_pass=32/32 checks=654 passed=654 failed=0
6   | suite    | strong_consistency       | 32/cawd | ✅ PASS    | 4/30s     | nodes_pass=32/32 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 32/cawd | ✅ PASS    | 7/30s     | nodes_pass=32/32 checks=80 passed=80 failed=0
8   | suite    | mmap_coherency           | 32/cawd | ✅ PASS    | 5/30s     | nodes_pass=32/32 checks=35 passed=35 failed=0
9   | suite    | zero_silent_loss         | 32/cawd | ✅ PASS    | 25/60s    | nodes_pass=32/32 checks=644 passed=644 failed=0
10  | suite    | dlm_fairness             | 32/cawd | ✅ PASS    | 15/30s    | nodes_pass=32/32 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 32/cawd | ✅ PASS    | 5/30s     | nodes_pass=32/32 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 32/cawd | ✅ PASS    | 11/90s    | nodes_pass=32/32 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 32/cawd | ✅ PASS    | 35/90s    | nodes_pass=32/32 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 32/cawd | ✅ PASS    | 21/60s    | nodes_pass=32/32 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 32/cawd | ✅ PASS    | 51/90s    | nodes_pass=32/32 checks=204 passed=204 failed=0
16  | suite    | dir_reuse_coherency      | 32/cawd | ✅ PASS    | 112/120s  | nodes_pass=32/32 checks=72 passed=72 failed=0
17  | suite    | fence_during_write       | 32/cawd | ✅ PASS    | 19/60s    | nodes_pass=32/32 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 32/cawd | ✅ PASS    | 9/60s     | nodes_pass=32/32 checks=5 passed=5 failed=0
19  | suite    | soak                     | 32/cawd | ✅ PASS    | 31/60s    | dur=30s ops=1227 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 32/cawd | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=32 dlm=cawd]



=== MXFS TEST STATUS — conditions — nodes=1 dlm=caw ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 1/caw   | ✅ PASS    | 0/300s    | skipped (marker matched 1/caw)
2   | suite    | precond_readiness        | 1/caw   | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | posix_single             | 1/caw   | ✅ PASS    | 2/15s     | checks=29 passed=29 failed=0
4   | suite    | fsx                      | 1/caw   | ✅ PASS    | 9/88s     | checks=2 passed=2 failed=0
5   | suite    | fio_verify               | 1/caw   | ✅ PASS    | 3/42s     | checks=3 passed=3 failed=0
6   | suite    | integrity_filetypes      | 1/caw   | ✅ PASS    | 2/10s     | checks=13 passed=13 failed=0
7   | suite    | fio_perf                 | 1/caw   | ✅ PASS    | 13/120s   | nodes_pass=1/1 seqW=1735MiB/s seqR=626MiB/s randW=32735iops randR=41690iops
8   | suite    | fio_perf_vs_xfs          | 1/caw   | ✅ PASS    | 1/10s     | seqW=98% seqR=113% randW=80% randR=158% worst(write)=80% (threshold>=70%, wsrc=xfs-baseline)
9   | suite    | cache_coherency          | 1/caw   | ✅ PASS    | 1/60s     | nodes_pass=1/1 checks=530 passed=530 failed=0
10  | suite    | strong_consistency       | 1/caw   | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=7 passed=7 failed=0
11  | suite    | posix_multi              | 1/caw   | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=266 passed=266 failed=0
12  | suite    | mmap_coherency           | 1/caw   | ✅ PASS    | 0/30s     | nodes_pass=1/1 checks=4 passed=4 failed=0
13  | suite    | zero_silent_loss         | 1/caw   | ✅ PASS    | 0/60s     | nodes_pass=1/1 checks=24 passed=24 failed=0
14  | suite    | dlm_fairness             | 1/caw   | ✅ PASS    | 1/30s     | nodes_pass=1/1 checks=5 passed=5 failed=0
15  | suite    | scaling_curve            | 1/caw   | ✅ PASS    | 1/90s     | nodes_pass=1/1 checks=7 passed=7 failed=0
16  | suite    | dlm_scaling              | 1/caw   | ✅ PASS    | 9/90s     | nodes_pass=1/1 checks=6 passed=6 failed=0
17  | suite    | rsync_paired             | 1/caw   | ✅ PASS    | 2/60s     | nodes_pass=1/1 checks=6 passed=6 failed=0
18  | suite    | fault_enospc             | 1/caw   | ✅ PASS    | 0/10s     | checks=4 passed=4 failed=0
19  | suite    | crash_consistency        | 1/caw   | ✅ PASS    | 2/90s     | nodes_pass=1/1 checks=54 passed=54 failed=0
20  | suite    | dir_reuse_coherency      | 1/caw   | ✅ PASS    | 77/120s   | nodes_pass=1/1 checks=170 passed=170 failed=0
21  | suite    | soak                     | 1/caw   | ✅ PASS    | 31/60s    | dur=30s ops=1835 errs=0 dmesg_hits=0
22  | tooling  | mkfs_timing              | 1/caw   | ✅ PASS    | 1/10s     | 215ms (threshold<=10000ms)
23  | tooling  | chk_clean                | 1/caw   | ✅ PASS    | 0/10s     | rc=0 errors=0
24  | tooling  | online_resize            | 1/caw   | ✅ PASS    | 12/25s    | pre=1695MB post=3743MB delta=2048MB/+2048MB data_intact=yes
25  | tooling  | dkms_install             | 1/caw   | ✅ PASS    | 104/240s  | add=0 build=0 install=0 installed=yes remove=0 clean=yes
26  | tooling  | single_node_paired       | 1/caw   | ✅ PASS    | 35/90s    | xfs=(3652/2723/2579/2793)ms mxfs=(2983/2994/2780/2663)ms round_ratios=81,95,107,109 ratio=101% files=8714/8714
27  | tooling  | fio_vs_xfs_baseline      | 1/caw   | ✅ PASS    | 123/180s  | seqW=932/734MiB rounds=70,126,97,43→83% randW=28093/23393iops rounds=156,120,63,220→138% worst_write=83% [reads cache-bound: seqR 119% randR 87%]
28  | tooling  | cluster_ops_timing       | 1/caw   | ✅ PASS    | 2/10s     | first=97ms rest=96ms umount=446ms
29  | tooling  | fault_io_error           | 1/caw   | ✅ PASS    | 3/60s     | nodes_pass=1/1 eio=yes wms=5 bad_dmesg=0 remount=yes data_intact=yes chk_rc=0
30  | caw      | dlm_lock_correctness     | 1/caw   | ✅ PASS    | 1/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 30 — 30 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=1 dlm=caw]

=== MXFS TEST STATUS — conditions — nodes=2 dlm=caw ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 2/caw   | ✅ PASS    | 0/300s    | skipped (marker matched 2/caw)
2   | suite    | precond_readiness        | 2/caw   | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 2/caw   | ✅ PASS    | 14/120s   | nodes_pass=2/2 seqW=2198MiB/s seqR=1120MiB/s randW=80589iops randR=74920iops
4   | suite    | fio_perf_vs_xfs          | 2/caw   | ✅ PASS    | 0/10s     | seqW=235% seqR=210% randW=101% randR=159% worst(write)=101% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 2/caw   | ✅ PASS    | 5/60s     | nodes_pass=2/2 checks=534 passed=534 failed=0
6   | suite    | strong_consistency       | 2/caw   | ✅ PASS    | 0/30s     | nodes_pass=2/2 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 2/caw   | ✅ PASS    | 1/30s     | nodes_pass=2/2 checks=140 passed=140 failed=0
8   | suite    | mmap_coherency           | 2/caw   | ✅ PASS    | 1/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
9   | suite    | zero_silent_loss         | 2/caw   | ✅ PASS    | 2/60s     | nodes_pass=2/2 checks=44 passed=44 failed=0
10  | suite    | dlm_fairness             | 2/caw   | ✅ PASS    | 3/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 2/caw   | ✅ PASS    | 3/30s     | nodes_pass=2/2 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 2/caw   | ✅ PASS    | 1/90s     | nodes_pass=2/2 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 2/caw   | ✅ PASS    | 12/90s    | nodes_pass=2/2 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 2/caw   | ✅ PASS    | 4/60s     | nodes_pass=2/2 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 2/caw   | ✅ PASS    | 4/90s     | nodes_pass=2/2 checks=104 passed=104 failed=0
16  | suite    | dir_reuse_coherency      | 2/caw   | ✅ PASS    | 103/120s  | nodes_pass=2/2 checks=163 passed=163 failed=0
17  | suite    | fence_during_write       | 2/caw   | ✅ PASS    | 17/60s    | nodes_pass=2/2 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 2/caw   | ✅ PASS    | 7/60s     | nodes_pass=2/2 checks=5 passed=5 failed=0
19  | suite    | soak                     | 2/caw   | ✅ PASS    | 32/60s    | dur=30s ops=1381 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 2/caw   | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=2 dlm=caw]

=== MXFS TEST STATUS — conditions — nodes=4 dlm=caw ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 4/caw   | ✅ PASS    | 0/300s    | skipped (marker matched 4/caw)
2   | suite    | precond_readiness        | 4/caw   | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 4/caw   | ✅ PASS    | 13/120s   | nodes_pass=4/4 seqW=2102MiB/s seqR=1808MiB/s randW=109318iops randR=120597iops
4   | suite    | fio_perf_vs_xfs          | 4/caw   | ✅ PASS    | 0/10s     | seqW=246% seqR=289% randW=87% randR=411% worst(write)=87% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 4/caw   | ✅ PASS    | 6/60s     | nodes_pass=4/4 checks=542 passed=542 failed=0
6   | suite    | strong_consistency       | 4/caw   | ✅ PASS    | 1/30s     | nodes_pass=4/4 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 4/caw   | ✅ PASS    | 2/30s     | nodes_pass=4/4 checks=80 passed=80 failed=0
8   | suite    | mmap_coherency           | 4/caw   | ✅ PASS    | 1/30s     | nodes_pass=4/4 checks=7 passed=7 failed=0
9   | suite    | zero_silent_loss         | 4/caw   | ✅ PASS    | 2/60s     | nodes_pass=4/4 checks=84 passed=84 failed=0
10  | suite    | dlm_fairness             | 4/caw   | ✅ PASS    | 6/30s     | nodes_pass=4/4 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 4/caw   | ✅ PASS    | 3/30s     | nodes_pass=4/4 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 4/caw   | ✅ PASS    | 2/90s     | nodes_pass=4/4 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 4/caw   | ✅ PASS    | 13/90s    | nodes_pass=4/4 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 4/caw   | ✅ PASS    | 14/60s    | nodes_pass=4/4 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 4/caw   | ✅ PASS    | 8/90s     | nodes_pass=4/4 checks=204 passed=204 failed=0
16  | suite    | dir_reuse_coherency      | 4/caw   | ✅ PASS    | 100/120s  | nodes_pass=4/4 checks=142 passed=142 failed=0
17  | suite    | fence_during_write       | 4/caw   | ✅ PASS    | 17/60s    | nodes_pass=4/4 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 4/caw   | ✅ PASS    | 7/60s     | nodes_pass=4/4 checks=5 passed=5 failed=0
19  | suite    | soak                     | 4/caw   | ✅ PASS    | 32/60s    | dur=30s ops=1375 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 4/caw   | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=4 dlm=caw]

=== MXFS TEST STATUS — conditions — nodes=8 dlm=caw ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 8/caw   | ✅ PASS    | 0/300s    | skipped (marker matched 8/caw)
2   | suite    | precond_readiness        | 8/caw   | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 8/caw   | ✅ PASS    | 12/120s   | nodes_pass=8/8 seqW=2244MiB/s seqR=3330MiB/s randW=180920iops randR=231194iops
4   | suite    | fio_perf_vs_xfs          | 8/caw   | ✅ PASS    | 0/10s     | seqW=198% seqR=616% randW=80% randR=540% worst(write)=80% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 8/caw   | ✅ PASS    | 8/60s     | nodes_pass=8/8 checks=558 passed=558 failed=0
6   | suite    | strong_consistency       | 8/caw   | ✅ PASS    | 2/30s     | nodes_pass=8/8 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 8/caw   | ✅ PASS    | 3/30s     | nodes_pass=8/8 checks=56 passed=56 failed=0
8   | suite    | mmap_coherency           | 8/caw   | ✅ PASS    | 2/30s     | nodes_pass=8/8 checks=11 passed=11 failed=0
9   | suite    | zero_silent_loss         | 8/caw   | ✅ PASS    | 4/60s     | nodes_pass=8/8 checks=164 passed=164 failed=0
10  | suite    | dlm_fairness             | 8/caw   | ✅ PASS    | 9/30s     | nodes_pass=8/8 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 8/caw   | ✅ PASS    | 4/30s     | nodes_pass=8/8 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 8/caw   | ✅ PASS    | 2/90s     | nodes_pass=8/8 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 8/caw   | ✅ PASS    | 14/90s    | nodes_pass=8/8 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 8/caw   | ✅ PASS    | 17/60s    | nodes_pass=8/8 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 8/caw   | ✅ PASS    | 15/90s    | nodes_pass=8/8 checks=404 passed=404 failed=0
16  | suite    | dir_reuse_coherency      | 8/caw   | ✅ PASS    | 105/120s  | nodes_pass=8/8 checks=121 passed=121 failed=0
17  | suite    | fence_during_write       | 8/caw   | ✅ PASS    | 17/60s    | nodes_pass=8/8 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 8/caw   | ✅ PASS    | 7/60s     | nodes_pass=8/8 checks=5 passed=5 failed=0
19  | suite    | soak                     | 8/caw   | ✅ PASS    | 32/60s    | dur=30s ops=1352 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 8/caw   | ✅ PASS    | 1/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=8 dlm=caw]

=== MXFS TEST STATUS — conditions — nodes=16 dlm=caw ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 16/caw  | ✅ PASS    | 0/300s    | skipped (marker matched 16/caw)
2   | suite    | precond_readiness        | 16/caw  | ✅ PASS    | 0/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 16/caw  | ✅ PASS    | 14/120s   | nodes_pass=16/16 seqW=2103MiB/s seqR=3495MiB/s randW=188234iops randR=395509iops
4   | suite    | fio_perf_vs_xfs          | 16/caw  | ✅ PASS    | 0/10s     | seqW=115% seqR=576% randW=80% randR=901% worst(write)=80% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 16/caw  | ✅ PASS    | 12/60s    | nodes_pass=16/16 checks=590 passed=590 failed=0
6   | suite    | strong_consistency       | 16/caw  | ✅ PASS    | 2/30s     | nodes_pass=16/16 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 16/caw  | ✅ PASS    | 3/30s     | nodes_pass=16/16 checks=56 passed=56 failed=0
8   | suite    | mmap_coherency           | 16/caw  | ✅ PASS    | 2/30s     | nodes_pass=16/16 checks=19 passed=19 failed=0
9   | suite    | zero_silent_loss         | 16/caw  | ✅ PASS    | 9/60s     | nodes_pass=16/16 checks=324 passed=324 failed=0
10  | suite    | dlm_fairness             | 16/caw  | ✅ PASS    | 14/30s    | nodes_pass=16/16 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 16/caw  | ✅ PASS    | 4/30s     | nodes_pass=16/16 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 16/caw  | ✅ PASS    | 4/90s     | nodes_pass=16/16 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 16/caw  | ✅ PASS    | 20/90s    | nodes_pass=16/16 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 16/caw  | ✅ PASS    | 17/60s    | nodes_pass=16/16 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 16/caw  | ✅ PASS    | 26/90s    | nodes_pass=16/16 checks=354 passed=354 failed=0
16  | suite    | dir_reuse_coherency      | 16/caw  | ✅ PASS    | 106/120s  | nodes_pass=16/16 checks=100 passed=100 failed=0
17  | suite    | fence_during_write       | 16/caw  | ✅ PASS    | 19/60s    | nodes_pass=16/16 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 16/caw  | ✅ PASS    | 8/60s     | nodes_pass=16/16 checks=5 passed=5 failed=0
19  | suite    | soak                     | 16/caw  | ✅ PASS    | 32/60s    | dur=30s ops=1340 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 16/caw  | ✅ PASS    | 1/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=16 dlm=caw]

=== MXFS TEST STATUS — conditions — nodes=32 dlm=caw ===
#   | CAT      | TEST                     | COND    | STATUS     | TIME      | MEASURED
----+----------+--------------------------+---------+------------+-----------+----------------------------
1   | suite    | prep_cluster             | 32/caw  | ✅ PASS    | 0/300s    | skipped (marker matched 32/caw)
2   | suite    | precond_readiness        | 32/caw  | ✅ PASS    | 1/10s     | checks=7 passed=7 failed=0
3   | suite    | fio_perf                 | 32/caw  | ✅ PASS    | 31/120s   | nodes_pass=32/32 seqW=7915MiB/s seqR=2489MiB/s randW=301099iops randR=485797iops
4   | suite    | fio_perf_vs_xfs          | 32/caw  | ✅ PASS    | 0/10s     | seqW=291% seqR=412% randW=91% randR=1733% worst(write)=91% (threshold>=70%, wsrc=raw-ceiling)
5   | suite    | cache_coherency          | 32/caw  | ✅ PASS    | 25/60s    | nodes_pass=32/32 checks=654 passed=654 failed=0
6   | suite    | strong_consistency       | 32/caw  | ✅ PASS    | 4/30s     | nodes_pass=32/32 checks=3 passed=3 failed=0
7   | suite    | posix_multi              | 32/caw  | ✅ PASS    | 7/30s     | nodes_pass=32/32 checks=80 passed=80 failed=0
8   | suite    | mmap_coherency           | 32/caw  | ✅ PASS    | 4/30s     | nodes_pass=32/32 checks=35 passed=35 failed=0
9   | suite    | zero_silent_loss         | 32/caw  | ✅ PASS    | 26/60s    | nodes_pass=32/32 checks=644 passed=644 failed=0
10  | suite    | dlm_fairness             | 32/caw  | ✅ PASS    | 16/30s    | nodes_pass=32/32 checks=5 passed=5 failed=0
11  | suite    | dlm_membership           | 32/caw  | ✅ PASS    | 6/30s     | nodes_pass=32/32 checks=5 passed=5 failed=0
12  | suite    | scaling_curve            | 32/caw  | ✅ PASS    | 11/90s    | nodes_pass=32/32 checks=8 passed=8 failed=0
13  | suite    | dlm_scaling              | 32/caw  | ✅ PASS    | 36/90s    | nodes_pass=32/32 checks=7 passed=7 failed=0
14  | suite    | rsync_paired             | 32/caw  | ✅ PASS    | 21/60s    | nodes_pass=32/32 checks=6 passed=6 failed=0
15  | suite    | crash_consistency        | 32/caw  | ✅ PASS    | 52/90s    | nodes_pass=32/32 checks=204 passed=204 failed=0
16  | suite    | dir_reuse_coherency      | 32/caw  | ✅ PASS    | 101/120s  | nodes_pass=32/32 checks=65 passed=65 failed=0
17  | suite    | fence_during_write       | 32/caw  | ✅ PASS    | 20/60s    | nodes_pass=32/32 checks=7 passed=7 failed=0
18  | suite    | fault_netpartition       | 32/caw  | ✅ PASS    | 18/60s    | nodes_pass=32/32 checks=5 passed=5 failed=0
19  | suite    | soak                     | 32/caw  | ✅ PASS    | 31/60s    | dur=30s ops=1263 errs=0 dmesg_hits=0
20  | caw      | dlm_lock_correctness     | 32/caw  | ✅ PASS    | 0/60s     | fua=ok caw=ok lba=131087
------------------------------------------------------------------------------------------
Total: 20 — 20 PASS, 0 FAIL, 0 SKIPPED, 0 PENDING   [conditions — nodes=32 dlm=caw]
```
