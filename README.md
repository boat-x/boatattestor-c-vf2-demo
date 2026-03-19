# BoAT Attestor (C)

BoAT Attestor (`boat-attest-c`) runs on a VisionFive2 RISC-V board and attests system metrics (memory, CPU usage, timestamp) to the HashAnchor blockchain attestation platform.

This is the C version, using the [BoAT v4 SDK](https://github.com/boat-x/BoAT4.git) for x402 pay-per-use payment signing. The BoAT4 SDK is built as a static library and linked into the program.

## Prerequisites

- VisionFive2 board running Debian Linux (riscv64)
- Network connectivity to HashAnchor (`hashanchor.xid.network`)
- A HashAnchor tenant account with a pre-registered device

### Build tools

- gcc
- make
- cmake (>= 3.12)
- git

### Libraries

- libcurl4-openssl-dev
- libcjson-dev
- libssl-dev

Install all build dependencies:

```bash
sudo apt-get install gcc make cmake git libcurl4-openssl-dev libcjson-dev libssl-dev
```

## Build

The Makefile automatically clones the BoAT4 SDK from GitHub and builds it as a static library on first run. No manual setup needed.

### Option A: Build locally on the board

Copy `boat-attest-c.c`, `Makefile`, and `deploy-local.sh` to `~/boatattestor-c/` on the board, then:

```bash
cd ~/boatattestor-c
make
```

Or use the helper script:

```bash
chmod +x deploy-local.sh
./deploy-local.sh build
```

### Option B: Deploy from a host machine via SSH

Edit `deploy-remote.sh` and set `BOARD` to your board's SSH host/alias, then:

```bash
chmod +x deploy-remote.sh
./deploy-remote.sh build
```

This copies the source files to the board and runs `make` remotely.

### Clean targets

```bash
make clean        # Remove the built binary
make boat4-clean  # Remove the BoAT4 build directory (forces library rebuild)
make distclean    # Remove everything including the cloned BoAT4 SDK
```

If you pull a new version of BoAT4 (e.g. `cd BoAT4 && git pull`), run `make boat4-clean` to rebuild the static library before the next `make`.

## Usage

### API Key Mode

```bash
./boat-attest-c --api-key ha_YOUR_API_KEY
```

Or set the environment variable:

```bash
export HASHANCHOR_API_KEY=ha_YOUR_API_KEY
./boat-attest-c
```

### x402 Pay-per-Use Mode

Run without `--api-key` to use x402 nanopayments:

```bash
./boat-attest-c
```

On first run, a wallet is created at `~/.boat-attest-wallet.json`. Fund it with USDC on Arc Testnet (chain ID 5042002) before use.

### Dry Run

Preview what would be attested without submitting:

```bash
./boat-attest-c --dry-run
```

## Configuration Files

| File | Location | Purpose |
|------|----------|---------|
| `.boat-attest-device.json` | `~/` | Ed25519 device keypair |
| `.boat-attest-wallet.json` | `~/` | Secp256k1 wallet for x402 payments |

Both files are created with 0600 permissions. Existing files (e.g. from the Python version) are loaded as-is to avoid fund loss.

## Verification

After a successful attestation, verify the hash on-chain:

```
https://hashanchor.xid.network/v1/verify/0xYOUR_HASH
```

## Periodic Attestation

To attest every hour via cron:

```bash
crontab -e
# Add:
0 * * * * ~/boatattestor-c/boat-attest-c --api-key ha_YOUR_API_KEY >> ~/boatattestor-c/attest.log 2>&1
```
