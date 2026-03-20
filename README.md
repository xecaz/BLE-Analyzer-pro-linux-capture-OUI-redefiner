# oui_lookup

A single-file C tool for enriching BLE sniffer captures with manufacturer information. Resolves device manufacturers from both IEEE OUI prefixes (public addresses) and BLE Company IDs embedded in advertising data (works for random addresses too).

Built to process captures from a WCH BLE sniffer. Accepts CSV files, pcap files (`DLT_BLUETOOTH_LE_LL_WITH_PHDR`), and live sniffer text piped via stdin.

## Build

```
make
```

Requires `gcc`. No external libraries.

## Setup

Download the OUI and BLE Company ID databases:

```
./oui_lookup --update
```

This fetches data from [maclookup.app](https://maclookup.app) (IEEE OUI mirror) and [Bluetooth SIG](https://bitbucket.org/bluetooth-SIG/public/) (Company Identifiers), then writes a binary database to `~/.oui_lookup.db`. Requires `curl`.

## Usage

### Enrich a CSV

```
./oui_lookup capture.csv -o enriched.csv
```

Appends three columns to the output:

| Column | Description |
|---|---|
| `address_type` | `public` or `random` (from PDU header TxAdd bit) |
| `oui_manufacturer` | IEEE OUI vendor name (public addresses only) |
| `ble_company` | BLE Company ID name from 0xFF AD type (any address) |

Without `-o`, output goes to stdout.

### Enrich live sniffer output

```
capture_tool | ./oui_lookup -
```

Reads WCH sniffer text lines from stdin, appends `| address_type | oui | company` to each packet line. Non-packet lines pass through unchanged. Output is flushed per-line for real-time use.

Expected input format:
```
[    33344834 us] ch37  ADV_NONCONN_IND  rssi  -68 dBm  AA 8E89BED6  E9:E7:8B:69:F8:49  PDU[16]: 42 0e 49 f8 69 8b e7 e9 07 ff 4c 00 12 02 ac 00
```

### Process a pcap file

```
./oui_lookup --pcap capture.pcap -o enriched.csv
```

Reads pcap files with link type 256 (`DLT_BLUETOOTH_LE_LL_WITH_PHDR`). Outputs enriched CSV with columns: `timestamp_us,channel,pdu_type,address,rssi_dbm,pdu_hex,address_type,oui_manufacturer,ble_company`.

### Summary

```
./oui_lookup --summary capture.csv
./oui_lookup --summary -                       # from sniffer text on stdin
./oui_lookup --summary --pcap capture.pcap     # from pcap file
```

Prints unique device counts grouped by OUI manufacturer and BLE Company ID, plus public/random address breakdown. Works with all three input modes.

### Single MAC lookup

```
./oui_lookup --mac DC:23:51:A3:F8:53
```

### Import from local files

```
./oui_lookup --import oui.json company_identifiers.yaml
```

Build the database from locally downloaded files instead of fetching.

## Input CSV format

Expects a header row with at least these columns (order doesn't matter):

- `address` — MAC address in `AA:BB:CC:DD:EE:FF` format
- `pdu_hex` — raw BLE advertising PDU as a hex string

The PDU hex must include the 2-byte header and 6-byte advertiser address, followed by AD structures. This is the format produced by the WCH BLE sniffer firmware.

## How it works

- **Address type**: determined from the TxAdd bit (bit 6 of the first PDU header byte). `1` = random, `0` = public.
- **OUI lookup**: the first 3 bytes of the MAC address are matched against the IEEE OUI database. Only meaningful for public addresses — random addresses have fabricated prefixes.
- **BLE Company ID**: the advertising payload is parsed as length-type-value AD structures. Type `0xFF` (Manufacturer Specific Data) contains a 16-bit Company ID (little-endian) assigned by the Bluetooth SIG. This works for both public and random addresses.
- **Database**: a compact binary file with sorted arrays, searched via `bsearch()`. ~57K OUI entries + ~4K Company IDs.

## Files

```
oui_lookup.c    Single-file C source (~1400 lines)
Makefile        Build with gcc -O2
~/.oui_lookup.db  Binary database (created by --update)
```
