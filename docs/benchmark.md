# MXFS Benchmark — Worker Runbook

Run all 4 standard benchmarks on a single MXFS node. The node is already prepped
and mounted at `/mnt/shared`. Replace HOSTNAME throughout with the assigned node name.

## MQTT Synchronization

Multi-node benchmarks use MQTT to ensure all nodes start each workload simultaneously.
Broker: `192.168.1.149`. The protocol for each workload is:

1. Node drops caches
2. Node publishes ready: `mosquitto_pub -h 192.168.1.149 -t bench/ready -m HOSTNAME`
3. Node waits for go: `mosquitto_sub -h 192.168.1.149 -t bench/go -C 1 > /dev/null`
4. Node runs fio

The Director collects all ready messages and publishes the go signal only after
every node has reported ready. Do NOT start fio without receiving the go signal.

For single-node benchmarks, skip the MQTT steps — just drop caches and run fio.

## 1. Verify Node is Ready

SSH to the node:
```
/src/mxfs/tools/mxfs_sshpass.sh HOSTNAME /tmp/.mxfs_pass "mountpoint -q /mnt/shared && which fio && which mosquitto_pub && echo READY"
```

If not READY, report BENCH_FAIL. If fio is missing:
```
/src/mxfs/tools/mxfs_sshpass.sh HOSTNAME /tmp/.mxfs_pass "apt-get update && apt-get install -y fio mosquitto-clients"
```

## 2. Run Sequential Write

```
/src/mxfs/tools/mxfs_sshpass.sh HOSTNAME /tmp/.mxfs_pass "sync && echo 3 > /proc/sys/vm/drop_caches && sleep 1 && mosquitto_pub -h 192.168.1.149 -t bench/ready -m \$(hostname) && mosquitto_sub -h 192.168.1.149 -t bench/go -C 1 > /dev/null && fio --name=seqwrite --filename=/mnt/shared/\$(hostname)/fio.dat --rw=write --bs=1m --size=4g --ioengine=libaio --direct=1 --iodepth=32 --runtime=60 --time_based --group_reporting --output-format=json > /tmp/fio_seqwrite.json 2>&1"
```

## 3. Run Sequential Read

The file from step 2 must exist.

```
/src/mxfs/tools/mxfs_sshpass.sh HOSTNAME /tmp/.mxfs_pass "sync && echo 3 > /proc/sys/vm/drop_caches && sleep 1 && mosquitto_pub -h 192.168.1.149 -t bench/ready -m \$(hostname) && mosquitto_sub -h 192.168.1.149 -t bench/go -C 1 > /dev/null && fio --name=seqread --filename=/mnt/shared/\$(hostname)/fio.dat --rw=read --bs=1m --size=4g --ioengine=libaio --direct=1 --iodepth=32 --runtime=60 --time_based --group_reporting --output-format=json > /tmp/fio_seqread.json 2>&1"
```

## 4. Run Random Write

```
/src/mxfs/tools/mxfs_sshpass.sh HOSTNAME /tmp/.mxfs_pass "sync && echo 3 > /proc/sys/vm/drop_caches && sleep 1 && mosquitto_pub -h 192.168.1.149 -t bench/ready -m \$(hostname) && mosquitto_sub -h 192.168.1.149 -t bench/go -C 1 > /dev/null && fio --name=randwrite --filename=/mnt/shared/\$(hostname)/fio.dat --rw=randwrite --bs=4k --size=256m --ioengine=libaio --direct=1 --iodepth=32 --runtime=60 --time_based --group_reporting --output-format=json > /tmp/fio_randwrite.json 2>&1"
```

## 5. Run Random Read

```
/src/mxfs/tools/mxfs_sshpass.sh HOSTNAME /tmp/.mxfs_pass "sync && echo 3 > /proc/sys/vm/drop_caches && sleep 1 && mosquitto_pub -h 192.168.1.149 -t bench/ready -m \$(hostname) && mosquitto_sub -h 192.168.1.149 -t bench/go -C 1 > /dev/null && fio --name=randread --filename=/mnt/shared/\$(hostname)/fio.dat --rw=randread --bs=4k --size=256m --ioengine=libaio --direct=1 --iodepth=32 --runtime=60 --time_based --group_reporting --output-format=json > /tmp/fio_randread.json 2>&1"
```

## 6. SCP Results to Host

```
sshpass -f /tmp/.mxfs_pass scp root@HOSTNAME:/tmp/fio_seqwrite.json /tmp/bench_HOSTNAME_seqwrite.json
sshpass -f /tmp/.mxfs_pass scp root@HOSTNAME:/tmp/fio_seqread.json /tmp/bench_HOSTNAME_seqread.json
sshpass -f /tmp/.mxfs_pass scp root@HOSTNAME:/tmp/fio_randwrite.json /tmp/bench_HOSTNAME_randwrite.json
sshpass -f /tmp/.mxfs_pass scp root@HOSTNAME:/tmp/fio_randread.json /tmp/bench_HOSTNAME_randread.json
```

## 7. Report

```
HOSTNAME: BENCH_OK
```
or
```
HOSTNAME: BENCH_FAIL step=N reason=DESCRIPTION
```

## Director-Side MQTT Protocol

The Director orchestrates multi-node benchmarks. For each workload:

```bash
# 1. Clear stale messages
mosquitto_pub -h 192.168.1.149 -t bench/ready -r -n
mosquitto_pub -h 192.168.1.149 -t bench/go -r -n

# 2. Subscribe for N ready messages (background)
mosquitto_sub -h 192.168.1.149 -t bench/ready -C N > /tmp/bench_ready.log &
READY_PID=$!
sleep 1

# 3. Launch all nodes (they drop caches, signal ready, wait for go)
for n in NODES; do
    SSH_CMD ... &
done

# 4. Wait for all ready
wait $READY_PID

# 5. GO
mosquitto_pub -h 192.168.1.149 -t bench/go -m start

# 6. Wait for fio completion
wait

# 7. SCP results from all nodes
```
