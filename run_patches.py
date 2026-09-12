#!/usr/bin/env python3
"""
Simple masterdata patch manager.
Reads IDs from config.json and runs patch_masterdata.py.
"""

import json
import os
import subprocess
import sys


def load_config(path="config.json"):
    if not os.path.exists(path):
        print(f"Error: config file '{path}' not found!")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get(cfg, key):
    """Return config value as string.
    If the value is a list of keys (*_ALL), recursively join them."""
    val = cfg.get(key, "")
    if isinstance(val, list):
        parts = []
        for k in val:
            parts.append(get(cfg, k))
        return ", ".join(p for p in parts if p)
    return str(val).strip() if val else ""


def run_patch(input_file, output, event_quests, banners, premium_shops,
              exchange_shops, exclude_consumables, rewrite_shop_content,
              rewrite_shop_count="", rewrite_shop_type=""):
    """Single call to patch_masterdata.py"""
    out_dir = os.path.dirname(output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    cmd = [
        sys.executable, "patch_masterdata.py",
        "--input", input_file,
        "--output", output,
        "--event-quests", event_quests,
        "--banners", banners,
        "--premium-shops", premium_shops,
        "--exchange-shops", exchange_shops,
        "--exclude-consumables", exclude_consumables,
        "--rewrite-shop-content", rewrite_shop_content,
        "--rewrite-shop-count", rewrite_shop_count,
        "--rewrite-shop-type", rewrite_shop_type,
    ]

    print(f"  → {output}")
    try:
        subprocess.run(cmd, check=True)
        print(f"    OK\n")
    except subprocess.CalledProcessError as e:
        print(f"    ERROR: {e}\n")
        sys.exit(1)


def main():
    cfg = load_config()

    # ============================================================
    # Variables from config
    # ============================================================
    INPUT = get(cfg, "INPUT")

    if not INPUT:
        print("Error: INPUT is empty in config.json")
        sys.exit(1)
    if not os.path.isfile(INPUT):
        print(f"Error: input file '{INPUT}' not found!")
        print("Put origin.bin.e in the same folder as this script (or fix INPUT in config.json).")
        sys.exit(1)

    # Events
    EVENTS_MAIN      = get(cfg, "EVENTS_MAIN")
    EVENTS_REC_ALL   = get(cfg, "EVENTS_REC_ALL")
    EVENTS_VAR_ALL   = get(cfg, "EVENTS_VAR_ALL")
    EVENTS_BONUS_ALL = get(cfg, "EVENTS_BONUS_ALL")

    # Gacha
    GACHA_PREM_ALL = get(cfg, "GACHA_PREM_ALL")
    GACHA_EVENT    = get(cfg, "GACHA_EVENT")

    # Shops
    SHOPS_MAIN      = get(cfg, "SHOPS_MAIN")
    SHOPS_EXTRA     = get(cfg, "SHOPS_EXTRA")
    SHOPS_GACHA_ALL = get(cfg, "SHOPS_GACHA_ALL")
    SHOPS_EVENT_ALL = get(cfg, "SHOPS_EVENT_ALL")
    SHOP_PREM       = get(cfg, "SHOP_PREM")

    # Consumables
    CONSUMABLES_ALL = get(cfg, "CONSUMABLES_ALL")

    # Rewrite
    SHOPCONTENT_COMP  = get(cfg, "SHOPCONTENT_COMP")
    SHOPCONTENT_MEDAL = get(cfg, "SHOPCONTENT_MEDAL")
    REWRITE_SHOP_CONTENT = f"{SHOPCONTENT_COMP}, {SHOPCONTENT_MEDAL}"

    # Optional rewrite flags (empty by default, add keys to config.json when needed)
    # Example in config: "SHOPCOUNT": "123:5:12, 456:10"
    # Example in config: "SHOPTYPE": "123:11:1, 456:2"
    SHOPCOUNT = get(cfg, "SHOPCOUNT")
    SHOPTYPE  = get(cfg, "SHOPTYPE")

    # Convenient pre-built combinations
    BANNERS_DEFAULT = f"{GACHA_PREM_ALL}, {GACHA_EVENT}"
    EXCLUDE_CONSUMABLES = CONSUMABLES_ALL

    # ============================================================
    # Menu
    # ============================================================
    print("========================================")
    print("        Masterdata Patch Manager        ")
    print("========================================")
    print("1. Single file with ALL content")
    print("2. Standard 6 variations")
    print("3. 18 advanced splits (advance/ folder)")
    print("0. Exit")
    print("========================================")

    choice = input("Select mode (1, 2, 3 or 0): ").strip()

    if choice == "0":
        print("Exiting.")
        sys.exit(0)

    # ============================================================
    # TASK 1 — full patch (everything at once)
    # ============================================================
    if choice == "1":
        print("\n=== TASK 1: Full patch ===\n")

        run_patch(
            input_file=INPUT,
            output="20240404193219.bin.e",
            event_quests=f"{EVENTS_MAIN}, {EVENTS_REC_ALL}, {EVENTS_VAR_ALL}, {EVENTS_BONUS_ALL}",
            banners=BANNERS_DEFAULT,
            premium_shops=SHOP_PREM,
            exchange_shops=f"{SHOPS_MAIN}, {SHOPS_EXTRA}, {SHOPS_GACHA_ALL}, {SHOPS_EVENT_ALL}",
            exclude_consumables=EXCLUDE_CONSUMABLES,
            rewrite_shop_content=REWRITE_SHOP_CONTENT,
            rewrite_shop_count=SHOPCOUNT,
            rewrite_shop_type=SHOPTYPE,
        )

    # ============================================================
    # TASK 2 — standard 6 variations
    # ============================================================
    elif choice == "2":
        print("\n=== TASK 2: Standard 6 variations ===\n")

        # 1. Full
        run_patch(
            input_file=INPUT,
            output="20240404193219.bin.e",
            event_quests=f"{EVENTS_MAIN}, {EVENTS_REC_ALL}, {EVENTS_VAR_ALL}, {EVENTS_BONUS_ALL}",
            banners=BANNERS_DEFAULT,
            premium_shops=SHOP_PREM,
            exchange_shops=f"{SHOPS_MAIN}, {SHOPS_EXTRA}, {SHOPS_GACHA_ALL}, {SHOPS_EVENT_ALL}",
            exclude_consumables=EXCLUDE_CONSUMABLES,
            rewrite_shop_content=REWRITE_SHOP_CONTENT,
            rewrite_shop_count=SHOPCOUNT,
            rewrite_shop_type=SHOPTYPE,
        )

        # 2. Clear
        run_patch(
            input_file=INPUT,
            output="20240404193219_Clear.bin.e",
            event_quests=EVENTS_MAIN,
            banners=BANNERS_DEFAULT,
            premium_shops=SHOP_PREM,
            exchange_shops=f"{SHOPS_MAIN}, {SHOPS_EXTRA}",
            exclude_consumables=EXCLUDE_CONSUMABLES,
            rewrite_shop_content=REWRITE_SHOP_CONTENT,
            rewrite_shop_count=SHOPCOUNT,
            rewrite_shop_type=SHOPTYPE,
        )

        # 3. Gacha
        run_patch(
            input_file=INPUT,
            output="20240404193219_Gacha.bin.e",
            event_quests=EVENTS_MAIN,
            banners=BANNERS_DEFAULT,
            premium_shops=SHOP_PREM,
            exchange_shops=f"{SHOPS_MAIN}, {SHOPS_EXTRA}, {SHOPS_GACHA_ALL}",
            exclude_consumables=EXCLUDE_CONSUMABLES,
            rewrite_shop_content=REWRITE_SHOP_CONTENT,
            rewrite_shop_count=SHOPCOUNT,
            rewrite_shop_type=SHOPTYPE,
        )

        # 4. Rec
        run_patch(
            input_file=INPUT,
            output="20240404193219_Rec.bin.e",
            event_quests=f"{EVENTS_MAIN}, {EVENTS_REC_ALL}",
            banners=BANNERS_DEFAULT,
            premium_shops=SHOP_PREM,
            exchange_shops=f"{SHOPS_MAIN}, {SHOPS_EXTRA}, {SHOPS_EVENT_ALL}",
            exclude_consumables=EXCLUDE_CONSUMABLES,
            rewrite_shop_content=REWRITE_SHOP_CONTENT,
            rewrite_shop_count=SHOPCOUNT,
            rewrite_shop_type=SHOPTYPE,
        )

        # 5. Var
        run_patch(
            input_file=INPUT,
            output="20240404193219_Var.bin.e",
            event_quests=f"{EVENTS_MAIN}, {EVENTS_VAR_ALL}",
            banners=BANNERS_DEFAULT,
            premium_shops=SHOP_PREM,
            exchange_shops=f"{SHOPS_MAIN}, {SHOPS_EXTRA}",
            exclude_consumables=EXCLUDE_CONSUMABLES,
            rewrite_shop_content=REWRITE_SHOP_CONTENT,
            rewrite_shop_count=SHOPCOUNT,
            rewrite_shop_type=SHOPTYPE,
        )

        # 6. Bonus
        run_patch(
            input_file=INPUT,
            output="20240404193219_Bonus.bin.e",
            event_quests=f"{EVENTS_MAIN}, {EVENTS_BONUS_ALL}",
            banners=BANNERS_DEFAULT,
            premium_shops=SHOP_PREM,
            exchange_shops=f"{SHOPS_MAIN}, {SHOPS_EXTRA}",
            exclude_consumables=EXCLUDE_CONSUMABLES,
            rewrite_shop_content=REWRITE_SHOP_CONTENT,
            rewrite_shop_count=SHOPCOUNT,
            rewrite_shop_type=SHOPTYPE,
        )

    # ============================================================
    # TASK 3 — 18 advanced splits
    # ============================================================
    elif choice == "3":
        print("\n=== TASK 3: 18 advanced splits ===\n")

        # --- Gacha 1..5 ---
        for i in range(1, 6):
            run_patch(
                input_file=INPUT,
                output=f"advance/20240404193219_Gacha_{i}.bin.e",
                event_quests=EVENTS_MAIN,
                banners=f"{get(cfg, f'GACHA_PREM_{i}')}, {GACHA_EVENT}",
                premium_shops=SHOP_PREM,
                exchange_shops=f"{SHOPS_MAIN}, {SHOPS_EXTRA}, {get(cfg, f'SHOPS_GACHA_{i}')}",
                exclude_consumables=EXCLUDE_CONSUMABLES,
                rewrite_shop_content=REWRITE_SHOP_CONTENT,
                rewrite_shop_count=SHOPCOUNT,
                rewrite_shop_type=SHOPTYPE,
            )

        # --- Rec 1..5 ---
        for i in range(1, 6):
            run_patch(
                input_file=INPUT,
                output=f"advance/20240404193219_Rec_{i}.bin.e",
                event_quests=f"{EVENTS_MAIN}, {get(cfg, f'EVENTS_REC_{i}')}",
                banners=BANNERS_DEFAULT,
                premium_shops=SHOP_PREM,
                exchange_shops=f"{SHOPS_MAIN}, {SHOPS_EXTRA}, {get(cfg, f'SHOPS_EVENT_{i}')}",
                exclude_consumables=EXCLUDE_CONSUMABLES,
                rewrite_shop_content=REWRITE_SHOP_CONTENT,
                rewrite_shop_count=SHOPCOUNT,
                rewrite_shop_type=SHOPTYPE,
            )

        # --- Var 1..4 ---
        for i in range(1, 5):
            run_patch(
                input_file=INPUT,
                output=f"advance/20240404193219_Var_{i}.bin.e",
                event_quests=f"{EVENTS_MAIN}, {get(cfg, f'EVENTS_VAR_{i}')}",
                banners=BANNERS_DEFAULT,
                premium_shops=SHOP_PREM,
                exchange_shops=f"{SHOPS_MAIN}, {SHOPS_EXTRA}",
                exclude_consumables=EXCLUDE_CONSUMABLES,
                rewrite_shop_content=REWRITE_SHOP_CONTENT,
                rewrite_shop_count=SHOPCOUNT,
                rewrite_shop_type=SHOPTYPE,
            )

        # --- Bonus 1..4 ---
        for i in range(1, 5):
            run_patch(
                input_file=INPUT,
                output=f"advance/20240404193219_Bonus_{i}.bin.e",
                event_quests=f"{EVENTS_MAIN}, {get(cfg, f'EVENTS_BONUS_{i}')}",
                banners=BANNERS_DEFAULT,
                premium_shops=SHOP_PREM,
                exchange_shops=f"{SHOPS_MAIN}, {SHOPS_EXTRA}",
                exclude_consumables=EXCLUDE_CONSUMABLES,
                rewrite_shop_content=REWRITE_SHOP_CONTENT,
                rewrite_shop_count=SHOPCOUNT,
                rewrite_shop_type=SHOPTYPE,
            )

    else:
        print("Invalid choice. Exiting.")
        sys.exit(1)

    print("=== Done ===")


if __name__ == "__main__":
    main()
