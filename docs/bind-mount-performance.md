# Mac bind mounts

Mac workspaces under `/opt` and `/usr/local` are host paths, like `/Users`
and `/Volumes`. Prefixes match whole path components: `/optical` and
`/usr/locality` are still VM paths. Linux paths such as `/lib/modules`
remain available for kind and other nested runtimes.

Several mounts can be used together. Keep source in a bind mount and put
Linux dependencies and generated caches in named volumes:

```yaml
services:
  app:
    image: node:22-alpine
    working_dir: /app
    volumes:
      - ./src:/app
      - ./config:/config:ro
      - node_modules:/app/node_modules
      - build_cache:/app/.cache
volumes:
  node_modules:
  build_cache:
```

Named volumes avoid a host/guest filesystem request for each dependency
file. This changes where those files live: back up important volume data
and keep source files in the bind mount.

The guest also sets read-ahead to 1024 KiB for the Mac virtiofs share only.
This batches sequential reads without lengthening metadata cache timeouts
or disabling host/guest change visibility. The tuning is best effort: if
the kernel has no backing-device setting, the share keeps its default.
Rosetta, the data disk and Linux host filesystems are not changed.

Measure the workload before choosing a filesystem layout. A sequential
read benchmark does not predict dependency installation or small-file
metadata performance, and warm host caches are not cold disk results.

`bench/bind-read.c` is a small Linux reader for measuring the transfer
without timing the Docker CLI. It reads in 1 MiB blocks and evicts only its
input file from the guest page cache before timing. It does not purge the
Mac's caches. Compile it for the guest architecture, for example:

```sh
zig cc -target aarch64-linux-musl -O2 bench/bind-read.c -o /tmp/bind-read
dd if=/dev/zero of=/tmp/bind-fixture.bin bs=1048576 count=512
docker run --rm --network none \
  -v /tmp/bind-read:/reader:ro \
  -v /tmp/bind-fixture.bin:/fixture:ro \
  alpine:3.22 /reader /fixture
```

Use identical file sizes, images, CPU/memory limits and read block sizes.
Warm the host cache in both arms and alternate their order. Preserve every
sample and label the measured runtime, kernel and hardware. The reader's
JSON reports bytes, elapsed seconds and MiB/s; it makes no speed assertion.

## Colima comparison, 2026-11-12

The local comparison used an M4 Max (128 GiB), macOS 15.8.2, Hyperfine
2.0.0 and Colima 0.10.3 with Docker 29.5.2. Both VMs had two ARM CPUs and
an 8 GiB ceiling, VirtioFS, identical Alpine config/layer bytes and the
same compiled reader. Kiri retained its dynamic balloon; Colima retained
its normal memory policy. The kernels differ: Kiri 6.18.58 and Colima
6.8.0-117-generic. This is a comparison of these configurations.

Each arm has twenty timed samples: ten in A/B order, then ten in B/A
order, with two warmups per block. Host caches are warm. `seq-cold` evicts
only the input file from the guest cache. These are Docker CLI end-to-end
latencies, including client startup; they do not isolate engine CPU cost.

| Workload | Kiri median, ms | Colima median, ms | Colima / Kiri |
|---|---:|---:|---:|
| API ping | 4.906 | 5.558 | 1.13 |
| Run and remove `true` | 23.386 | 77.501 | 3.31 |
| Exec `true` | 19.969 | 33.480 | 1.68 |
| Read 512 MiB, guest fixture evicted | 109.468 | 164.801 | 1.51 |
| Read 512 MiB, repeated | 110.615 | 159.103 | 1.44 |
| Stat 4,096 small files | 20.493 | 38.418 | 1.87 |
| Open/read/close 4,096 small files | 693.562 | 554.711 | 0.80 |
| Write 64 files with fdatasync, then fsync directory | 36.534 | 48.290 | 1.32 |
| CPU fixture including exec | 49.458 | 66.180 | 1.34 |

The small-file read workload remains slower on Kiri in this configuration.
Turning off the balloon did not resolve it. Increasing read-ahead to
4096 KiB made sequential reads about 29% slower. Reducing it to 512 KiB
gave only 3–4%, below the predeclared 5% adoption threshold, with no useful
small-file gain. Keep 1024 KiB; no additional runtime setting was adopted.

For immutable Linux dependencies, avoiding the host boundary has a much
larger effect. A separate four-arm comparison read the same 4,096 files
from host binds and named volumes on both engines. Every copied file was
SHA-256 checked before timing.

| Dependency storage | Kiri median, ms | Colima median, ms |
|---|---:|---:|
| Host bind | 698.717 | 603.852 |
| Named Linux volume | 22.427 | 41.137 |

That layout change made Kiri's fixture 31.15 times faster. Comparing the
same volume layout, Kiri was 1.83 times faster than Colima. A named volume
is separate storage: it does not mirror subsequent host edits. Keep source
in binds, initialize dependencies inside Linux, and preserve volume data
when it is important. These fixture ratios do not predict an entire build
or application speedup.

`bench/io-workload.c` is the exact reader used for this comparison. Build
it with `zig cc -target aarch64-linux-musl -static -O3`. Modes are
`seq-cold`, `seq-warm`, `metadata`, `small-read`, `durable-write` and `cpu`;
the second argument is the data directory. Sequential modes expect a
512 MiB `fixture.bin`; small-file modes expect `tree/f0000.dat` through
`f4095.dat`, each containing 256 bytes of value `index % 251`.
`durable-write` expects an existing `writes` directory. For example, create
the small-file corpus with this optional Bun command in the data directory:

```sh
bun -e 'import{mkdirSync,writeFileSync}from"node:fs";mkdirSync("tree",{recursive:true});for(let i=0;i<4096;i++)writeFileSync(`tree/f${String(i).padStart(4,"0")}.dat`,Buffer.alloc(256,i%251));'
```

Run the reader inside a persistent container for each engine, for example
`docker --context kiri exec io-bench /reader small-read /data`, through
Hyperfine with `--warmup 2 --runs 10 --export-json results.json`. Reverse
engine order for a second block. Keep the source, data, mount layout and
VM limits fixed; do not mix host binds with volumes in an engine-only claim.

`bench/colima-hyperfine-2026-11-12.json` contains source and fixture hashes,
medians, exploratory bootstrap intervals, host-client CPU/RSS, empirical
tails and rejected candidates. With only twenty samples, reported p99 is
the empirical maximum; it is not a stable production-tail estimate.
