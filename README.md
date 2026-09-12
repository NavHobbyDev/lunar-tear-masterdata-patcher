# lunar-tear-masterdata-patcher

Utility scripts for patching encrypted masterdata binaries used with community private-server setups for a discontinued game.

Special thanks to **Walter Sparrow** for the original `patch_masterdata.py`  
→ [lunar-scripts](https://gitlab.com/walter-sparrow-group/lunar-scripts)

## What this patch changes

- Removes duplicate events
- Sorts quests by group: main → record → variation → bonus
- Cleans the premium shop (keeps only entries with original items)
- Removes duplicate event-medal exchange shops
- Removes unused gacha-medal exchange shops
- Sorts gacha banners according to the order defined in the config (currently alphabetical)
- **Shop “Countdown Resurrected Event Medal Vol.2”:** replaces companions that are already obtainable from events with companions that were otherwise unavailable without a database editor
- **Shop “Medals”:** replaces stamina exchange items with **Countdown Resurrected Event Medals** and **Mama Points**, so you can use the Countdown Resurrected Event shop (event characters, weapons, companions) and Mama Points (Remnants) without editing the user database
- Removes event stamina items (so they no longer clutter the stamina refill list)
- Removes event tickets (obtained from variation quests) that belong to event gachas not present in the current server version
- Removes Term Mama medals and their exchange shop

## Requirements

- Python 3
- Packages: `pycryptodome`, `msgpack`, `lz4`

Install dependencies:

```bash
# Windows
setup.bat

# Linux / macOS
chmod +x setup.sh && ./setup.sh
```

Or manually:

```bash
python -m pip install pycryptodome msgpack lz4
```

## Quick start

1. Put these files in the **same folder**:
   - `patch_masterdata.py`
   - `run_patches.py`
   - `config.json`
   - `patch.bat` (Windows) **or** `patch.sh` (Linux/macOS)
   - Your masterdata file (rename it to `origin.bin.e`)

2. Make sure the input file is named:

   ```text
   origin.bin.e
   ```

   (`origin` = original input; the script will not overwrite it.)

3. Run the launcher:

   ```bash
   # Windows
   patch.bat

   # Linux / macOS
   chmod +x patch.sh
   ./patch.sh
   ```

   Or directly:

   ```bash
   python run_patches.py
   ```

4. Choose a mode from the menu:

   | Option | Description |
   |--------|-------------|
   | **1** | Single file with **all** content |
   | **2** | Standard **6 variations** |
   | **3** | **18 advanced splits** (saved into `advance/` folder) |
   | **0** | Exit |

5. Copy the variant you want to:

   ```text
   server/assets/release/20240404193219.bin.e
   ```

   Rename it to exactly `20240404193219.bin.e` if needed.

6. Restart the **server** and **client**.

You can switch variants anytime: replace the file under `server/assets/release/` and restart the server and client.

## Output variants

### Mode 2 — Standard 6 variations

| File | Contents |
|------|----------|
| `20240404193219.bin.e` | **Full** — main + record + variation + bonus subquests, all selected shops |
| `20240404193219_Clear.bin.e` | **Lightest** — main subquests + banners only (best for story playthrough) |
| `20240404193219_Gacha.bin.e` | Main subquests + **gacha medal** exchange shops |
| `20240404193219_Rec.bin.e` | Main + **record** subquests + **event medal** exchange shops |
| `20240404193219_Var.bin.e` | Main + **variation** subquests |
| `20240404193219_Bonus.bin.e` | Main + **bonus** subquests |

### Mode 3 — Advanced 18 splits

They contain less data for the client to process, which reduces client load:

- `advance/20240404193219_Gacha_1.bin.e` … `_Gacha_5.bin.e`
- `advance/20240404193219_Rec_1.bin.e` … `_Rec_5.bin.e`
- `advance/20240404193219_Var_1.bin.e` … `_Var_4.bin.e`
- `advance/20240404193219_Bonus_1.bin.e` … `_Bonus_4.bin.e`

## Configuration (`config.json`)

All IDs are defined in `config.json`. Edit this file to change which events, banners, shops, etc. are included.

Key groups:

| Key | Purpose |
|-----|---------|
| `EVENTS_MAIN` / `EVENTS_REC_*` / `EVENTS_VAR_*` / `EVENTS_BONUS_*` | Event quest chapter IDs |
| `GACHA_PREM_*` / `GACHA_EVENT` | Gacha banner IDs |
| `SHOPS_MAIN` / `SHOPS_EXTRA` / `SHOPS_GACHA_*` / `SHOPS_EVENT_*` | Exchange / medal shop IDs |
| `SHOP_PREM` | Premium shop IDs |
| `CONSUMABLES_*` | Consumable items that should **keep** their original end dates (not extended) |
| `SHOPCONTENT_COMP` / `SHOPCONTENT_MEDAL` | PossessionId rewrites inside shop item content |
| `SHOPCOUNT` / `SHOPTYPE` | Optional count / type rewrites (empty by default) |

`*_ALL` keys are lists of other keys and are expanded automatically.

### Useful tips

- **Restore event tickets**  
  Remove `"CONSUMABLES_EVENT_TICKET"` from the `"CONSUMABLES_ALL"` list in `config.json`.

- **Remove a specific gacha**  
  Look up its banner ID and exchange-shop ID in `IDs.md`, then delete those IDs from the corresponding `GACHA_PREM_*` and `SHOPS_GACHA_*` entries.

## License and attribution

**This repository** (modifications, extra flags, batch/shell wrappers, docs) is released under the [MIT License](LICENSE).

The core `patch_masterdata.py` logic is derived from the public [lunar-scripts](https://gitlab.com/walter-sparrow-group/lunar-scripts) project (`patch_masterdata.py`). That upstream repository did **not** publish an explicit license file at the time this work was created. Upstream code remains the work of its original authors; this repo does not claim to re-license their work beyond use of a publicly posted script for community tooling.

If you are the upstream author and want a different credit line, license note, or removal, open an issue or contact the maintainer.

Documentation and some code extensions were written with AI assistance;
the maintainer reviewed and verified the final result.

### Disclaimer

Not affiliated with Square Enix, Applibot, or the Lunar Tear server project.  
This tool does not distribute game clients, assets, or official binaries.  
You must provide your own data files. Use at your own risk.
