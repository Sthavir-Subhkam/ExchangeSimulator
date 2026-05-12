# NSE FO Exchange Simulator

Standalone NSE FO exchange simulator that mirrors the `devel/adapters/output/NSE/DirectIf`
session flow used by the existing infra:

- TLS gateway-router request/response
- secure box registration
- encrypted FO session
- FO login, system info, update-local-db, heartbeat
- single-leg trimmed FO limit and IOC orders with immediate full fills

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

## Notes

- The simulator is FO-only.
- Recovery replay is stubbed: `7000` gets an immediate `7031`.
- Unsupported order shapes return trimmed order error `20231`.
- Order fills are full and immediate unless `fill_delay_us` is configured.
- Post-fill order modifications return trimmed modification error `20042`.
