# ETHBLK - a high-performance disk over L2/L3 network protocol

Ethblk got its aspiration in AOE - ATA-over-Ethernet. It does not
support ATA, but can send disk blocks over Ethernet in a highly
efficient manner. It was designed not to repeat locking, false cache
sharing and serialization problems found in AOE implementation.

Ethblk runs entirely in kernel mode, supports both target and
initiator modes.

The work is still in progress, expect to see a lot of kernel crashes
and freezes, missing/incomplete/wrong documentation and frequent API
changes. Bug reports and all kinds of suggestions are more than
welcome!

For setup look at scripts/ethblk-setup. These variables need to be
changed according to your configuration:

```
nic=enp1s0
ini=1
tgt=0
tgt_ip=192.168.51.1
tgt_disk=/dev/nvme0n1
ini_ip=192.168.51.51
ini_mac=50:6b:4b:cc:f3:e6
```

By default, all messages above debug level are logged. For debug do
next:

`echo module ethblk +p | sudo tee /sys/kernel/debug/dynamic_debug/control`

Ethblk is a Linux-only thing as of now.

### Brief performance comparison of local disk vs NVMe-over-TCP vs ethblk:

##### Native NVMe on target (AMD EPYC 7281, Samsung EVO 970 Plus):
```
fio --filename=/dev/nvme0n1 --rw=randread --bs=4k --iodepth=128 --numjobs=8 --direct=1  --ioengine=libaio --name=foo --time_based --runtime=60 --group_reporting 
   read: IOPS=725k, BW=2831MiB/s (2969MB/s)(166GiB/60002msec)
    slat (usec): min=2, max=775, avg= 4.66, stdev= 2.52
    clat (usec): min=27, max=6656, avg=1404.75, stdev=346.46
     lat (usec): min=33, max=6667, avg=1410.02, stdev=346.85
```
##### NVMe-over-TCP on initator (Intel i7-3770, 100 GbE Mellanox MT27800):
```
fio --filename=/dev/nvme0n1 --rw=randread --bs=4k --iodepth=128 --numjobs=8 --direct=1  --ioengine=libaio --name=foo --time_based --runtime=60 --group_reporting 
   read: IOPS=284k, BW=1109MiB/s (1163MB/s)(65.0GiB/60002msec)
    slat (nsec): min=1870, max=31525k, avg=23475.22, stdev=61532.82
    clat (usec): min=102, max=54285, avg=3578.57, stdev=1215.20
     lat (usec): min=120, max=54308, avg=3602.40, stdev=1222.01
```

##### NVMe over ethblk on initiator (Intel i7-3770, 100 GbE Mellanox MT27800):
```
fio --filename=/dev/eda0 --rw=randread --bs=4k --iodepth=128 --numjobs=8 --direct=1  --ioengine=libaio --name=foo --time_based --runtime=60 --group_reporting 
   read: IOPS=703k, BW=2748MiB/s (2881MB/s)(161GiB/60003msec)
    slat (usec): min=2, max=26063, avg= 7.17, stdev=33.72
    clat (usec): min=41, max=28778, avg=1446.18, stdev=777.30
     lat (usec): min=51, max=28787, avg=1453.59, stdev=779.13
```
