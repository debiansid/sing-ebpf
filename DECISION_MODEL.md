# eBPF decision boundary

`sing-ebpf` is a data-plane library. Its policy boundary is the final action
performed by the kernel program:

- `DecisionPass`: leave the packet or socket operation alone;
- `DecisionIntercept`: redirect or assign it to the eBPF listener.

The library must not know why an action was selected. Concepts such as DNS
mode, FakeIP, route rule-sets, private-address policy, package names, or
sing-box configuration compatibility belong to sing-box. sing-box compiles
those inputs into action rules before updating the eBPF data plane.

The generic rule primitives in `decision.go` are deliberately limited to the
match key and the final action. A rule does not carry an `include`, `exclude`,
`bypass`, or `hijack` meaning. Those are sing-box policy concepts.

## Consumer integration contract

The `ActionPolicy` shape is a transport for final actions, not a second
configuration schema. The consumer must construct only the fields supported by
the selected data planes:

| Scope | Supported final-action inputs | Owned by the consumer |
| --- | --- | --- |
| local | UID, destination CIDR, destination port | UID/package selection, DNS/FakeIP/private/rule-set priority |
| shared | source CIDR, source MAC, destination CIDR, destination port | downstream selection and source-policy meaning |
| endpoint / vpn-server | destination CIDR, destination port | conjoint match cross-product, VPN tunnel readiness gating |

The current sing-box adapter enforces this mapping before calling the library:
local source CIDR/MAC and shared UID decisions are invalid for its four data
paths. Other consumers must apply the same integration-side validation rather
than relying on sing-ebpf to interpret or reject application scope semantics.

The library still validates every primitive action, range, prefix, protocol,
capacity, and ABI constraint that it can express. It does not validate whether
a valid primitive belongs to a particular application's local/shared model.

## Runtime status

All four data paths now have action-level update entry points:

1. cgroup socket hooks: `CgroupBackend.UpdateDestinationDecisions`;
2. local TC: `TCBackend.UpdateLocalDestinationDecisions`;
3. shared TC socket assignment: `TCBackend.UpdateSharedDestinationDecisions`;
4. shared packet rewrite: `SharedPacketRewriteBackend.UpdateDestinationDecisions`.

The process tracker likewise accepts `UIDDecision` values and a final default
action. Dynamic rule-set changes are compiled by sing-box into canonical
destination `pass` decisions before they cross this boundary. The library
keeps transactional map replacement, default action handling, self-bypass,
flow cleanup, and capability-selected fallback behavior.

The selector-based API has been removed. The root package intentionally exposes
only final-action policy construction and action-level runtime updates. This
prevents downstream callers from accidentally treating the library as a
second sing-box configuration compiler. Static action policy is constructed
when a backend is prepared; a configuration reload should replace that
backend/inbound rather than mutate selector state in place.

The mutable destination-action entry points are deliberately narrower: they
are for sing-box's dynamic rule-set pass updates only. They replace the
destination pass map transactionally and do not reinterpret DNS, FakeIP,
private-address, UID, package, MAC, or port configuration. Process tracking
also receives only final UID actions and is enabled by sing-box according to
its `router.NeedFindProcess()` decision.

### Endpoint / VPN-server bypass gate and TCP flow pinning

In addition to static action policy, local TC supports an endpoint / VPN-server
bypass gate (`ActionPolicy.EndpointCIDR` and `ActionPolicy.EndpointPort`).
Traffic matching both an endpoint destination CIDR and an endpoint port is
gated by the `SB_TC_FLAG_ENDPOINT_READY` control flag:

1. **Before readiness** (`ready=false`): matching traffic is forced into
   interception (`intercept=1`), directing it into the consumer router.
2. **After readiness** (`ready=true`): matching traffic bypasses local TC
   natively in the kernel (`intercept=0`).

The consumer updates this gate dynamically via:
`TCBackend.SetEndpointVPNReady(ready bool) error`

**TCP flow pinning contract**:
- Upon receiving a TCP SYN packet matching the endpoint gate, the kernel program
  pins the initial decision (`intercept=1` or `intercept=0`) together with the
  flow key and `socket_cookie` into the `tc_endpoint_flow` LRU hash map (capacity 8192).
- Subsequent packets of the established TCP connection look up this pinned entry
  and preserve the original decision for the duration of the flow.
- This prevents TCP connections from being reset or encountering broken state
  when the VPN readiness toggles during an active session.
- UDP traffic evaluates the live `SB_TC_FLAG_ENDPOINT_READY` flag per packet,
  migrating to the native direct path once the tunnel becomes ready.

### Runtime mutation rule

An exported update method is not a promise that every field in `ActionPolicy`
is mutable. Backends accept immutable hook capabilities, listener endpoints,
map capacities, and static UID/source/port actions at construction time. The
only supported post-start update is a destination CIDR list containing final
`DecisionPass` actions, and it is intentionally exposed as a narrow
destination-update method on each backend. A caller that needs any other
change must construct a new backend and atomically replace the consumer's
inbound. This keeps policy compilation in sing-box and prevents a future
method from accidentally becoming a second, partially implemented
configuration API.

## Ownership matrix

| Concern | sing-box | sing-ebpf |
| --- | --- | --- |
| JSON/config validation | yes | no |
| VPN tunnel interface readiness detection | yes | no |
| Endpoint/VPN gate control flag & TCP flow pinning | no | yes |
| DNS/FakeIP/rule-set meaning | yes | no |
| UID/package/MAC/CIDR/port priority | yes | no |
| Compile a final pass/intercept decision | yes | no |
| BPF map key ABI and updates | no | yes |
| cgroup/TC attachment and fallback | no | yes |
| socket assignment, packet rewrite and cleanup | no | yes |
| one-shot runtime/occupancy diagnostics | no | yes |

Data-plane parameters that are required to execute an action remain library
inputs: listener descriptors, redirect prefixes, interfaces, cgroup path,
map capacities, and network-generation state. They are not policy decisions.

The migration is intentionally ordered by blast radius: cgroup first, then
local TC, shared TC socket assignment, and finally shared packet rewrite. A
path is not considered migrated merely because its Go type contains
`Decision`; its native program must consume action-valued maps and its tests
must prove pass/intercept behavior for overlapping rules and update rollback.
