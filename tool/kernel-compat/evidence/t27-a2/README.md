# T27-A2 repair verification

Attempt: T27-A2 (repair of the T27-A1 review findings). Base checkpoint:
`674bc51`. All commands ran with an independent
`CARGO_TARGET_DIR=/private/var/folders/.../t27-a2-target` so no shared target
directory was reused.

| command | result | log |
| --- | --- | --- |
| `cargo test --manifest-path native-kernel/Cargo.toml --locked` | exit 0, 19 `test result: ok` suites, 0 failures | `default-tests.log` |
| `cargo test --manifest-path native-kernel/Cargo.toml --locked --features ios-vpn` | first run: the unrelated `tests/groups.rs::provider_registration_keeps_the_first_expected_status_for_a_shared_url` flaked under the parallel run; the isolated case passed and two full reruns were exit 0 (20 suites each) | `ios-tests.log` (final passing run) |
| `cargo test --manifest-path native-kernel/Cargo.toml --locked --features android-vpn` | exit 0, 20 `test result: ok` suites | `android-tests.log` |
| `node tool/kernel-compat/option-probe.mjs --rust <release billow-kernel> --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 --out tool/kernel-compat/evidence/option-matrix.txt` | exit 0; 287 no-op / 50 implemented / 179 enabled / 135 `rust=reject mihomo=accept` / 0 problems | `option-probe.log`, `../option-matrix.txt` |
| `node --test tool/kernel-compat/runner.test.mjs` | 10/10 pass | `runner.log` |
| `node tool/kernel-compat/t5-differential.mjs ... --effective-dir tool/kernel-compat/evidence/t5-effective` | 12/12 pass, 0 differ, 0 startup-failed | `t5.log` |
| `node tool/kernel-compat/t23-differential.mjs ...` | 28/28 (27 cases + persistence), 0 differ | `t23.log` |
| `node tool/kernel-compat/t24-differential.mjs ...` | 36 pass, 2 skipped, 0 differ (38 cases; the script records the connection-framing byte differences separately) | `t24.log` |
| `node tool/kernel-compat/t25-differential.mjs ...` | 47/49 equal, 2 known divergences, 0 unexpected | `t25.log` |

Targeted repair evidence:

- `tests/protocols.rs::ssh_outbound_basic_options_use_the_shared_dialer` —
  valid BasicOption knobs reach the SSH peer; an unbindable interface fails
  before the SSH handshake.
- `tests/ios_tunnel.rs::socks5_udp_datagrams_cross_the_tunnel_in_both_directions`
  — device IP packet through a SOCKS5 UDP association and back.
- `tests/protocols.rs::certificate_and_private_key_present_a_client_certificate`
  — CA-signed client identity accepted by an mTLS server, refused without it.
- `tests/protocols.rs::shadowsocks_udp_hop_dialer_options_own_the_hop_socket`
  — a chained UDP association applies the hop's `ip-version`, not the exit's.
- `src/outbound/tuic.rs::tests::cwnd_only_applies_to_bbr` — `cwnd` is consumed
  only by the BBR branch, matching the pinned `SetCongestionController`.
