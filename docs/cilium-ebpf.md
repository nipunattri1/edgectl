# Using cilium/ebpf (v0.22.0)

This project loads an eBPF collection with `bpf2go` and attaches it with
`cilium/ebpf`. Versions and file paths here match the Go rewrite in
`internal/` and `cmd/`.

## 1. Mental model

Four objects, four lifetimes:

| Object | Created by | Keeps alive | Destroyed when |
|---|---|---|---|
| `*ebpf.Map` | kernel on load | the map fd (and programs that use it) | `Close()` or last ref |
| `*ebpf.Program` | kernel on load | program fd (and links/maps referencing it) | `Close()` or last ref |
| `link.Link` | `link.AttachXDP` / `link.AttachTCX` | its fd | `Close()` (or pin keeps it alive) |
| `CollectionSpec` | `bpf2go` embedding | n/a | in-process only |

A program that is attached **through a link** disappears when the link's fd
closes *unless* the link was pinned. That is the whole point of pinning.

## 2. Generating the spec

`internal/gen/gen.go`:

```go
//go:generate go tool bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall" EdgeWall ../../bpf/firewall.bpf.c
```

Run with `just generate`. The generated `EdgeWallObjects` is the struct your
code assigns into:

```go
objs := gen.EdgeWallObjects{}
err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{...})
```

## 3. Loading a collection

```go
spec, err := gen.LoadEdgeWall()
if err != nil { ... }

objs := gen.EdgeWallObjects{}
collOpts := &ebpf.CollectionOptions{
    Programs: ebpf.ProgramOptions{
        LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats,
    },
    Maps: ebpf.MapOptions{
        PinPath: pinDir, // only matters for PinByName maps
    },
}
if err := spec.LoadAndAssign(&objs, collOpts); err != nil {
    if ve, ok := err.(*ebpf.VerifierError); ok {
        // ve contains the full kernel verifier log
    }
    return err
}
```

`LoadAndAssign` is what creates the kernel objects and fills `objs`. Always
`Close()` what you load; leaked fds keep programs and maps alive.

## 4. Map pinning (the easy part to get wrong)

`ebpf.MapOptions.PinPath` is **only** used when a map's `MapSpec.Pinning ==
ebpf.PinByName`. Otherwise it is ignored and nothing is pinned.

Two ways to make pinning happen.

### A. Declare it in the BPF C

Add a `pinning` member to the map definition:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, FirewallConfig);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} config_map SEC(".maps");
```

Then `bpf2go` records `Pinning: ebpf.PinByName` in the generated spec, and
`LoadAndAssign` with `PinPath` pins the map at `<PinPath>/<map_name>`. On a
later load, if a compatible pinned map exists, it is **reused** instead of
creating a new one.

### B. Pin explicitly from Go

```go
if err := objs.ConfigMap.Pin(filepath.Join(pinDir, "config_map")); err != nil { ... }
```

`Map.Pin` / `Map.Unpin` and `Map.Close` manage the lifecycle.

### Reuse rules

- Reuse happens only when `spec.Pinning == PinByName` and the pinned map is
  **compatible** (`MapSpec.Compatible` checks type, key/value size, max
  entries, flags).
- An incompatible pinned map returns an error rather than being overwritten.
- You can also hand in already-loaded maps via
  `CollectionOptions.MapReplacements` (they are `Clone()`d internally).

## 5. Program and map pinning for reuse

```go
// persist
prog.Pin("/sys/fs/bpf/xdp_firewall/prog") // programs can be pinned too
link.Pin("/sys/fs/bpf/xdp_firewall/prog_link")

// later process
prog, err := ebpf.LoadPinnedProgram(path, nil)
m,    err := ebpf.LoadPinnedMap(path, nil)
lnk,  err := link.LoadPinnedLink(path, nil)
```

`LoadPinned*` returns an object whose lifetime you own: `Close()` it when
done. Unpinning (`Unpin()`) removes the bpffs entry; the object stays alive
until the last reference closes.

## 6. Attaching and pinning links

```go
xdpOpts := link.XDPOptions{Program: objs.XdpFirewall, Interface: ni.Index}
switch mode {
case "generic": xdpOpts.Flags = link.XDPGenericMode
case "driver", "native": xdpOpts.Flags = link.XDPDriverMode
case "offload": xdpOpts.Flags = link.XDPOffloadMode
}
xdpLink, err := link.AttachXDP(xdpOpts)
if err != nil { ... }

// persist across processes (requires kernel 5.7+)
if err := xdpLink.Pin(filepath.Join(pinDir, "prog_link")); err != nil { ... }
```

TCX (kernel 6.6+):

```go
ingress, err := link.AttachTCX(link.TCXOptions{
    Program: objs.HandleIngress, Interface: ifindex,
    Attach: ebpf.AttachTCXIngress,
})
```

A link that is **not** pinned is destroyed on `Close()` (and usually detaches
the program). A pinned link survives process exit and keeps the program
attached.

## 7. Cleanup / detach pattern

Order matters: close live links, then remove pins, then close objects.

```go
func (l *Loader) Close() error {
    for _, lnk := range l.links { lnk.Close() } // detach
    for _, p := range pinPaths {
        os.Remove(p) // unlink; last ref gone -> destroy
    }
    if l.objects != nil { l.objects.Close() }
    return nil
}
```

`os.Remove` on a pinned bpffs entry is the unpin. Leaving it pinned keeps the
object alive even after your process dies — that is either the feature (daemon
restart) or a leak (forgot to unpin on detach).

## 8. Verifier logging

```go
collOpts := &ebpf.CollectionOptions{
    Programs: ebpf.ProgramOptions{
        LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats,
        LogSizeStart: 64 * 1024,
    },
}
```

On load failure, cast to `*ebpf.VerifierError` to print the kernel log. The
library retries with a growing buffer, so leave `LogSizeStart` at the default
unless you are debugging a huge program.

## 9. rlimit

```go
if err := rlimit.RemoveMemlock(); err != nil { ... }
```

Required on kernels < 5.11 for non-root loading; harmless and cheap on newer
ones. Call it before loading.

## 10. Common pitfalls (seen in this repo)

1. **`PinPath` alone pins nothing.** It only applies to `PinByName` maps.
   Fix the map definition or pin explicitly.
2. **Map name mismatch.** `NewPinPaths` uses `manual_block_map`, but the map
   is `manual_blacklist_map`. The pinned path and the map name must agree.
3. **`LoadPinned` that re-loads the spec** creates fresh maps instead of
   reusing pinned ones and never touches pinned links. Use
   `ebpf.LoadPinnedMap` / `link.LoadPinnedLink`.
4. **Pins removed on `Close()`.** If `start` defers `Close()`, pins live only
   while the process runs. For a persistent firewall you want a daemon or a
   detach command that unlinks explicitly.
5. **TCX requires kernel 6.6+.** `link.AttachTCX` returns a feature error
   otherwise; fall back to classic TC.
6. **Flood maps are unpinned by design** in the C code. Do not add them to
   the unpin list without checking that they were pinned.
7. **Attach mode.** `link.AttachXDP` with `Flags == 0` is "auto". Passing
   `XDPDriverMode` on a non-XDP-capable NIC fails; pick by capability.

## 11. Inspecting from the shell

```sh
ip -details link show dev enp0s20f0u4          # XDP prog id
sudo bpftool net list                          # xdp + tc + tcx
sudo bpftool link list                          # pinned links
sudo bpftool prog list | grep -E 'xdp_firewall|handle_ingress|handle_egress'
sudo bpftool map show pinned /sys/fs/bpf/xdp_firewall/config_map
sudo ls -l /sys/fs/bpf/xdp_firewall            # pin files
```

## 12. Minimal attach example (matches this project)

```go
func NewLoader(cfg config.Config) (*Loader, error) {
    fwCfg, _ := cfg.ToBpfConfig()
    rlimit.RemoveMemlock()
    ni, _ := net.InterfaceByName(cfg.Interface.Device)
    os.MkdirAll(cfg.PinDir, 0755)

    spec, _ := gen.LoadEdgeWall()
    objs := gen.EdgeWallObjects{}
    if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
        Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch},
        Maps:     ebpf.MapOptions{PinPath: cfg.PinDir},
    }); err != nil { return nil, err }

    objs.ConfigMap.Update(uint32(0), &fwCfg, ebpf.UpdateAny)

    xdpLink, err := link.AttachXDP(link.XDPOptions{
        Program: objs.XdpFirewall, Interface: ni.Index,
    })
    if err != nil { objs.Close(); return nil, err }
    xdpLink.Pin(filepath.Join(cfg.PinDir, "prog_link"))

    return &Loader{objects: &objs, links: []link.Link{xdpLink}, pinDir: cfg.PinDir}, nil
}
```

## References

- `internal/bpf/attach.go` — `NewLoader`, `LoadPinned`, `Close`
- `internal/gen/gen.go` — `bpf2go` invocation
- `bpf/maps.bpf.h` — map definitions (add `pinning` here)
- `include/common.h` — pin paths used by the C CLI