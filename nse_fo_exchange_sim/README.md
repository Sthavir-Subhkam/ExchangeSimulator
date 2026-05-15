# NSE FO Exchange Simulator

Standalone NSE FO exchange simulator that mirrors the `devel/adapters/output/NSE/DirectIf`
session flow used by the existing infra:

- TLS gateway-router request/response
- secure box registration
- encrypted FO session
- FO login, system info, update-local-db, heartbeat
- single-leg trimmed FO limit and IOC orders with immediate full fills
- single-leg trimmed FO new, modify, and cancel requests
- immediate single-leg IOC handling
- optional multicast/UDP TBT-driven book building and top-of-book matching

## Build

```bash
cmake -S nse_fo_exchange_sim -B build/nse_fo_exchange_sim
cmake --build build/nse_fo_exchange_sim
ctest --test-dir build/nse_fo_exchange_sim --output-on-failure
```

## Run

```bash
./build/nse_fo_exchange_sim/nse_fo_exchange_sim --config nse_fo_exchange_sim/config/example.conf
```

The config format is simple `key=value` text.

`market_data_stream` may be repeated and uses:

```text
market_data_stream=<host>:<port>@<interface_ip>
```

Examples:

```text
market_data_stream=239.10.10.1:32001@10.0.0.5
market_data_stream=127.0.0.1:32001@0.0.0.0
```

## Notes

- The simulator is FO-only.
- Recovery replay is stubbed: `7000` gets an immediate `7031`.
- Unsupported order shapes return trimmed order error `20231`.
- Order fills are full and immediate unless `fill_delay_us` is configured.
- Post-fill order modifications return trimmed modification error `20042`.
- Unsupported order shapes return trimmed order errors.
- Without any `market_data_stream` entries, accepted orders keep the older immediate-fill behavior.
- With `market_data_stream` configured, the simulator:
  - builds books only for token ids listed in `token_filter_file`
  - caps active books at `max_book_contracts`
  - ignores market-data ticks for tokens outside the token file
  - rests day-limit orders until top-of-book becomes marketable
  - checks IOC orders against the current top-of-book and cancels any unfilled remainder
- Matching is intentionally simple:
  - day-limit orders can fill partially and keep their remaining quantity open
  - IOC orders can fill partially and return a cancellation confirmation for the leftover quantity
  - fill price is the current top-of-book price on the opposite side
  - each book update exposes the current top-of-book quantity once for matching across resting simulator orders
  - the simulator does not persistently consume or alter the external market-data book when it fills client orders
