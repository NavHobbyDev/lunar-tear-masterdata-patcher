#!/usr/bin/env python3
"""Patch master data timestamps to extend content availability.

Decrypts the MasterMemory binary (.bin.e), extends EndDatetime fields from
the 2020-2029 range to 2099-12-31, and re-encrypts with the same AES key/IV.

Per-ID visibility: edit SELECTED_IDS below (or pass --event-quests /
--banners / --premium-shops / --exchange-shops on the command line) to pick
exactly which event quests, gacha banners and premium/exchange shops get
extended to 2099. Every other row of a selected category gets its EndDatetime
forced to 2020 so the client hides it. A category left as None keeps the old
"extend everything" behavior.

When a category is given as a list (CLI flags or a list in SELECTED_IDS),
visible rows are also re-ranked in that exact listed order.
  - m_event_quest_chapter: SortOrder (col 2) + DisplaySortOrder (col 10)
  - m_mom_banner:          SortOrderDesc (col 1), gacha banners only
                           (higher value first; list[0] gets the highest rank)
  - m_shop:                SortOrderInShopGroup (col 2), ranks restart per group

Ads are always suppressed regardless of the selections: non-gacha m_mom_banner
rows (event / premium-shop carousel ads), m_navi_cut_in (home-screen news
cut-ins) and m_appeal_dialog (login popup) are force-expired to 2020.

Consumable exclusions come only from --exclude-consumables (same comma /
range syntax as the other flags). Items listed there keep their original
EndDatetime; omit the flag or pass an empty value to bump every consumable.

Requires: pip install pycryptodome msgpack lz4
"""

import argparse
import os
import re
import struct
import sys
from datetime import datetime, timezone

import lz4.block
import msgpack
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


DEFAULT_INPUT = os.path.join("server", "assets", "release", "20240404193219.bin.e")
DEFAULT_KEY = "36436230313332314545356536624265"
DEFAULT_IV  = "45666341656634434165356536446141"

TARGET_END_DT = datetime(2099, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
TARGET_END_MS = int(TARGET_END_DT.timestamp() * 1000)
MIN_PATCH_MS  = int(datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp() * 1000)
MAX_PATCH_MS  = int(datetime(2099, 1, 1, tzinfo=timezone.utc).timestamp() * 1000)

# EndDatetime unselected rows are forced to this (2020-01-01) so the client
# treats them as long-expired and hides them. Same sentinel mama-s-toolkit uses.
EXPIRED_END_MS  = MIN_PATCH_MS
# Future StartDatetime of a selected row is pulled back to this (2000-01-01)
# so the client shows content that was never released.
PAST_START_MS   = int(datetime(2000, 1, 1, tzinfo=timezone.utc).timestamp() * 1000)

# --- Per-ID visibility selection --------------------------------------------
# None            -> patch every row of the category (old "show all" behavior).
# list of ids     -> ONLY these ids are extended to 2099; all other rows of
#                    the category are expired (EndDatetime -> 2020, hidden).
#                    Display order follows this list (first id = first on screen).
#                    An empty list hides the whole category.
# set of ids      -> same visibility filter, but order falls back to sorted(ids)
#                    because a set has no sequence — use a list to control order.
# CLI flags --event-quests / --banners / --premium-shops / --exchange-shops
# ("1,2,10-20" style) override these values when given; listed order is kept.
SELECTED_IDS = {
    'event_quests':   None,  # m_event_quest_chapter.EventQuestChapterId
    'banners':        None,  # m_mom_banner.MomBannerId (gacha banners only)
    'premium_shops':  None,  # m_shop.ShopId with ShopGroupType=1 (premium)
    'exchange_shops': None,  # m_shop.ShopId with ShopGroupType=4 (exchange)
}
# m_mom_banner note: the selection only ever affects GACHA banners
# (DestinationDomainType=1). All non-gacha banners (event / premium-shop-item
# ads in the menu carousel) are force-expired unconditionally — an empty set
# hides the whole carousel including gacha.

# Table/column facts for the managed categories (server's entities.go order).
SHOP_GROUP_PREMIUM  = 1   # m_shop.ShopGroupType for the premium shop
SHOP_GROUP_EXCHANGE = 4   # m_shop.ShopGroupType for the exchange (medal) shop
BANNER_DOMAIN_GACHA = 1   # m_mom_banner.DestinationDomainType for gacha

# Enhance keeps only the universal *_ALL targets ({1,2,3}); everything else
# (per-character, per-costume, per-weapon, per-attribute, per-series, per-id)
# is dropped to avoid extending entity-specific rerun boosts forever.
ENTITY_ID_TARGETS_ENHANCE = frozenset({11, 12, 13, 21, 22, 23, 31, 32})
ENTITY_ID_TARGETS_QUEST   = frozenset({5, 7})  # MAIN_QUEST_QUEST_ID, SUB_QUEST_QUEST_ID

SKIP_TABLES  = frozenset({"m_omikuji"})
EMPTY_TABLES = frozenset({"m_maintenance"})

# Ad/promo tables are force-EXPIRED (EndDatetime -> 2020 on every row,
# regardless of the original value): m_navi_cut_in is the home-screen
# "news"/cut-in advertisement layer — 8 of its rows ship with year-9999 ends
# so they'd stay active even unpatched; m_appeal_dialog is the banner-ad
# popup shown at login. Plain skipping is not enough, hence the forced expire.
EXPIRED_AD_TABLES = {
    'm_navi_cut_in': 4,    # EndDatetime column
    'm_appeal_dialog': 5,  # EndDatetime column
}

# Unhide the Labyrinth (EventQuestType=12) in the side-quest menu — the client
# hides every chapter of any EventQuestType missing from m_event_quest_unlock_condition.
TABLE_ROW_ADDITIONS = {
    'm_event_quest_unlock_condition': [
        [12, 0, 0, 1, 21, 0],
    ],
}

# Client cap MaxGimmickSequenceSchedule = 1024. Through 2023-02 there are 1022
# entries, so anything started after that cutoff stays expired.
SCHEDULE_PATCH_CUTOFF_MS = int(datetime(2023, 2, 1, tzinfo=timezone.utc).timestamp() * 1000)
TABLE_PATCH_FILTERS = {
    'm_gimmick_sequence_schedule': (1, SCHEDULE_PATCH_CUTOFF_MS),
}

# Column indices derived from entity class definitions in schemas.json.
# m_enhance_campaign and m_quest_campaign are intentionally absent — they're
# handled by patch_campaign_dedup() instead of the blanket bump.
# m_event_quest_chapter / m_shop are here as the fallback used while their
# SELECTED_IDS category is None; once a selection is configured they're
# routed to patch_managed_table() instead. m_mom_banner is ALWAYS routed to
# patch_managed_table() (non-gacha banners must be force-expired).
PATCH_COLUMNS = {
    'm_big_hunt_schedule': [(3, 'ChallengeEndDatetime')],
    'm_cage_ornament': [(2, 'EndDatetime')],
    'm_consumable_item_term': [(2, 'EndDatetime')],
    'm_costume_collection_bonus': [(6, 'EndDatetime')],
    'm_dokan': [(4, 'EndDatetime')],
    'm_event_quest_chapter': [(9, 'EndDatetime')],
    'm_event_quest_daily_group': [(2, 'EndDatetime')],
    'm_event_quest_guerrilla_free_open': [(4, 'EndDatetime')],
    'm_event_quest_limit_content': [(6, 'EndDatetime')],
    'm_event_quest_limit_content_deck_restriction': [(4, 'EndDatetime')],
    'm_gacha_medal': [(4, 'AutoConvertDatetime')],
    'm_gimmick_sequence_schedule': [(2, 'EndDatetime')],
    'm_important_item_effect': [(6, 'EndDatetime')],
    'm_login_bonus': [(5, 'EndDatetime'), (6, 'StampReceiveEndDatetime')],
    'm_mission_pass': [(2, 'EndDatetime')],
    'm_mission_term': [(2, 'EndDatetime')],
    'm_mom_point_banner': [(4, 'EndDatetime')],
    'm_omikuji': [(2, 'EndDatetime')],
    'm_portal_cage_access_point_function_group_schedule': [(5, 'EndDatetime')],
    'm_possession_acquisition_route': [(7, 'EndDatetime')],
    'm_premium_item': [(3, 'EndDatetime')],
    'm_pvp_season': [(3, 'SeasonEndDatetime')],
    'm_quest_bonus_term_group': [(3, 'EndDatetime')],
    'm_quest_schedule': [(3, 'EndDatetime')],
    'm_shop': [(10, 'EndDatetime')],
    'm_shop_item_cell_term': [(2, 'EndDatetime')],
    'm_tip': [(6, 'EndDatetime')],
    'm_title_flow_movie': [(3, 'EndDatetime')],
    'm_webview_mission': [(5, 'EndDatetime')],
    'm_webview_panel_mission': [(4, 'EndDatetime')],
}

# Campaign-family layout for the unified dedup helper.
CAMPAIGN_CFG = {
    'enhance': dict(
        family='enhance',
        target_table='m_enhance_campaign_target_group',
        effect_table=None,
        id_col=0, tg_col=1, eff_type_col=2, eff_val_col=3,
        start_col=4, end_col=5, user_status_col=6,
        entity_id_targets=ENTITY_ID_TARGETS_ENHANCE,
    ),
    'quest': dict(
        family='quest',
        target_table='m_quest_campaign_target_group',
        effect_table='m_quest_campaign_effect_group',
        id_col=0, tg_col=1, eff_group_col=2,
        start_col=3, end_col=4, user_status_col=5,
        entity_id_targets=ENTITY_ID_TARGETS_QUEST,
    ),
}


# --- LZ4/ExtType helpers ---

def read_lz4_ext_header(ext_data):
    """Strip the msgpack int prefix C#'s LZ4MessagePack writes before the LZ4 bytes."""
    tag = ext_data[0]
    if tag == 0xd2: return struct.unpack('>i', ext_data[1:5])[0], ext_data[5:]
    if tag == 0xce: return struct.unpack('>I', ext_data[1:5])[0], ext_data[5:]
    if tag == 0xd1: return struct.unpack('>h', ext_data[1:3])[0], ext_data[3:]
    if tag == 0xcd: return struct.unpack('>H', ext_data[1:3])[0], ext_data[3:]
    if tag <= 0x7f: return tag, ext_data[1:]
    raise ValueError(f"Unexpected msgpack tag 0x{tag:02x} in LZ4 ext header")


def build_lz4_ext_blob(decompressed_data):
    compressed = lz4.block.compress(decompressed_data, store_size=False)
    header = b'\xd2' + struct.pack('>i', len(decompressed_data))
    return msgpack.packb(msgpack.ExtType(99, header + compressed), use_bin_type=True)


# --- Msgpack binary walker ---
# Hand-rolled to support in-place int64 mutation: msgpack.packb re-encodes
# C#'s int64 columns as Python's tighter int encodings, producing byte-different
# blobs the client's schema validator rejects. So writes use this walker;
# read-only inspection can use msgpack.unpackb freely.

def skip_msgpack_value(data, pos):
    tag = data[pos]
    if tag <= 0x7f or tag >= 0xe0: return pos + 1
    if 0xa0 <= tag <= 0xbf:        return pos + 1 + (tag & 0x1f)
    if 0x90 <= tag <= 0x9f:
        n = tag & 0x0f
        p = pos + 1
        for _ in range(n): p = skip_msgpack_value(data, p)
        return p
    if 0x80 <= tag <= 0x8f:
        n = tag & 0x0f
        p = pos + 1
        for _ in range(n * 2): p = skip_msgpack_value(data, p)
        return p
    FIXED = {
        0xc0: 1, 0xc2: 1, 0xc3: 1,
        0xca: 5, 0xcb: 9,
        0xcc: 2, 0xcd: 3, 0xce: 5, 0xcf: 9,
        0xd0: 2, 0xd1: 3, 0xd2: 5, 0xd3: 9,
        0xd4: 3, 0xd5: 4, 0xd6: 6, 0xd7: 10, 0xd8: 18,
    }
    if tag in FIXED: return pos + FIXED[tag]
    LENGTH_PREFIXED = {
        0xc4: (1, 'B'), 0xc5: (2, '>H'), 0xc6: (4, '>I'),
        0xd9: (1, 'B'), 0xda: (2, '>H'), 0xdb: (4, '>I'),
        0xc7: (1, 'B'), 0xc8: (2, '>H'), 0xc9: (4, '>I'),
    }
    if tag in LENGTH_PREFIXED:
        sz_bytes, fmt = LENGTH_PREFIXED[tag]
        n = struct.unpack(fmt, data[pos + 1:pos + 1 + sz_bytes])[0]
        extra = 1 if tag in (0xc7, 0xc8, 0xc9) else 0
        return pos + 1 + sz_bytes + extra + n
    ARRAY_MAP = {0xdc: (2, '>H'), 0xdd: (4, '>I'), 0xde: (2, '>H'), 0xdf: (4, '>I')}
    if tag in ARRAY_MAP:
        sz_bytes, fmt = ARRAY_MAP[tag]
        n = struct.unpack(fmt, data[pos + 1:pos + 1 + sz_bytes])[0]
        items = n * 2 if tag in (0xde, 0xdf) else n
        p = pos + 1 + sz_bytes
        for _ in range(items): p = skip_msgpack_value(data, p)
        return p
    raise ValueError(f"Unknown msgpack tag 0x{tag:02x} at pos {pos}")


def read_array_len(data, pos):
    tag = data[pos]
    if 0x90 <= tag <= 0x9f: return (tag & 0x0f, pos + 1)
    if tag == 0xdc:         return (struct.unpack('>H', data[pos + 1:pos + 3])[0], pos + 3)
    if tag == 0xdd:         return (struct.unpack('>I', data[pos + 1:pos + 5])[0], pos + 5)
    raise ValueError(f"Expected array at pos {pos}, got tag 0x{tag:02x}")


def read_int(data, pos):
    tag = data[pos]
    if tag <= 0x7f: return tag
    if tag == 0xcc: return data[pos + 1]
    if tag == 0xcd: return struct.unpack('>H', data[pos + 1:pos + 3])[0]
    if tag == 0xce: return struct.unpack('>I', data[pos + 1:pos + 5])[0]
    if tag == 0xd3: return struct.unpack('>q', data[pos + 1:pos + 9])[0]
    raise ValueError(f"read_int: unexpected tag 0x{tag:02x} at pos {pos}")


# --- Table-blob mutators ---
# Each takes a bytearray of the decompressed table blob and mutates in place.

def add_table_rows(blob, rows, key_col=0):
    """Append rows whose key isn't already present. Idempotent."""
    count, pos = read_array_len(blob, 0)
    existing = set()
    p = pos
    for _ in range(count):
        _, row_pos = read_array_len(blob, p)
        existing.add(read_int(blob, row_pos))
        p = skip_msgpack_value(blob, p)
    to_add = [r for r in rows if r[key_col] not in existing]
    if not to_add:
        return None
    total = count + len(to_add)
    if total <= 0x0f:    header = bytes([0x90 | total])
    elif total <= 0xffff: header = b'\xdc' + struct.pack('>H', total)
    else:                 header = b'\xdd' + struct.pack('>I', total)
    new_rows = b''.join(msgpack.packb(r, use_bin_type=True) for r in to_add)
    return header + bytes(blob[pos:]) + new_rows


def patch_table_blob(blob, col_indices, row_filter=None, exclude_ids=None):
    """Bump int64 datetime columns in col_indices to TARGET_END_MS.
    exclude_ids is (id_col, id_set): rows whose id_col value is in id_set are
    left untouched (their original expired dates stay as they are)."""
    row_count, pos = read_array_len(blob, 0)
    patched = skipped = excluded = 0
    for _ in range(row_count):
        col_count, p = read_array_len(blob, pos)

        exclude_row = False
        if exclude_ids is not None:
            ex_col, ex_set = exclude_ids
            if ex_col == 0 and read_int(blob, p) in ex_set:
                exclude_row = True

        skip_row = False
        if row_filter is not None:
            filter_col, filter_max = row_filter
            fp = p
            for ci in range(min(filter_col + 1, col_count)):
                if ci == filter_col and blob[fp] == 0xd3:
                    val = struct.unpack('>q', blob[fp + 1:fp + 9])[0]
                    if val >= filter_max:
                        skip_row = True
                    break
                fp = skip_msgpack_value(blob, fp)

        if exclude_row or skip_row:
            if exclude_row:
                excluded += 1
            else:
                skipped += 1
            for _ in range(col_count): p = skip_msgpack_value(blob, p)
        else:
            for col_i in range(col_count):
                if col_i in col_indices and blob[p] == 0xd3:
                    val = struct.unpack('>q', blob[p + 1:p + 9])[0]
                    if MIN_PATCH_MS <= val <= MAX_PATCH_MS:
                        struct.pack_into('>q', blob, p + 1, TARGET_END_MS)
                        patched += 1
                p = skip_msgpack_value(blob, p)
        pos = p
    return patched, skipped, excluded


def expire_table_end(blob, end_col):
    """Force every row's EndDatetime cell to EXPIRED_END_MS regardless of its
    current value — ad tables ship rows with year-9999 ends that plain
    skipping would leave active. Returns the number of rewritten cells."""
    row_count, pos = read_array_len(blob, 0)
    expired = 0
    for _ in range(row_count):
        col_count, p = read_array_len(blob, pos)
        cp = p
        col_pos = []
        for _ in range(col_count):
            col_pos.append(cp)
            cp = skip_msgpack_value(blob, cp)
        if end_col < col_count and blob[col_pos[end_col]] == 0xd3:
            ep = col_pos[end_col]
            val = struct.unpack('>q', blob[ep + 1:ep + 9])[0]
            if val != EXPIRED_END_MS:
                struct.pack_into('>q', blob, ep + 1, EXPIRED_END_MS)
                expired += 1
        pos = cp
    return expired


# --- Per-ID selection mutator -----------------------------------------------
# Used for m_event_quest_chapter / m_mom_banner / m_shop when their
# SELECTED_IDS category is configured: selected ids go to 2099, the rest of
# the category is expired so the client hides it.

def rewrite_end(blob, p, target_ms):
    """Rewrite an int64 datetime cell to target_ms when patchable: any value
    from 2020 up to (but not past) TARGET_END_MS — some rows ship with
    far-future ends like 2099-07-01 that must be overridable too. Returns
    True if a write happened."""
    if blob[p] != 0xd3:
        return False
    val = struct.unpack('>q', blob[p + 1:p + 9])[0]
    if MIN_PATCH_MS <= val < TARGET_END_MS and val != target_ms:
        struct.pack_into('>q', blob, p + 1, target_ms)
        return True
    return False


def patch_managed_table(blob, end_col, start_col, classify, now_ms):
    """Drive per-row EndDatetime patching from a classifier.

    classify(blob, col_pos) -> (action, owner) where action is:
      'extend' — selected id: EndDatetime -> TARGET_END_MS; a StartDatetime
                 parked in the future is pulled to PAST_START_MS;
      'expire' — not selected: EndDatetime -> EXPIRED_END_MS (hidden),
                 forced unconditionally (even far-future year-9999 ends);
      'bump'   — outside the managed scope: old blanket bump to 2099.
    owner names the SELECTED_IDS category (for missing-id reports) or None.
    Returns (extended, expired, bumped, starts_pulled, found_ids_by_owner).
    """
    row_count, pos = read_array_len(blob, 0)
    extended = expired = bumped = starts = 0
    found = {}
    for _ in range(row_count):
        col_count, p = read_array_len(blob, pos)
        col_pos = []
        cp = p
        for _ in range(col_count):
            col_pos.append(cp)
            cp = skip_msgpack_value(blob, cp)
        action, owner = classify(blob, col_pos)
        if owner is not None:
            found.setdefault(owner, set()).add(read_int(blob, col_pos[0]))
        if action == 'extend':
            if rewrite_end(blob, col_pos[end_col], TARGET_END_MS):
                extended += 1
            sp = col_pos[start_col]
            if blob[sp] == 0xd3:
                sv = struct.unpack('>q', blob[sp + 1:sp + 9])[0]
                if sv > now_ms:
                    struct.pack_into('>q', blob, sp + 1, PAST_START_MS)
                    starts += 1
        elif action == 'expire':
            ep = col_pos[end_col]
            if blob[ep] == 0xd3:
                val = struct.unpack('>q', blob[ep + 1:ep + 9])[0]
                if val != EXPIRED_END_MS:
                    struct.pack_into('>q', blob, ep + 1, EXPIRED_END_MS)
                    expired += 1
        elif action == 'bump':
            if rewrite_end(blob, col_pos[end_col], TARGET_END_MS):
                bumped += 1
        pos = cp
    return extended, expired, bumped, starts, found


def classify_event_quest(selection):
    def classify(blob, col_pos):
        row_id = read_int(blob, col_pos[0])
        return ('extend' if row_id in selection else 'expire'), 'event_quests'
    return classify


def classify_banner(selection):
    def classify(blob, col_pos):
        if read_int(blob, col_pos[2]) != BANNER_DOMAIN_GACHA:
            return 'expire', None  # event/premium ads: always hidden
        if selection is None:
            return 'bump', None    # no selection: keep every gacha banner
        row_id = read_int(blob, col_pos[0])
        return ('extend' if row_id in selection else 'expire'), 'banners'
    return classify


def classify_shop(premium_sel, exchange_sel):
    def classify(blob, col_pos):
        group = read_int(blob, col_pos[1])
        if group == SHOP_GROUP_PREMIUM:
            sel, owner = premium_sel, 'premium_shops'
        elif group == SHOP_GROUP_EXCHANGE:
            sel, owner = exchange_sel, 'exchange_shops'
        else:
            return 'bump', None  # item/recovery/other shops keep blanket behavior
        if sel is None:
            return 'bump', None
        row_id = read_int(blob, col_pos[0])
        return ('extend' if row_id in sel else 'expire'), owner
    return classify


def parse_id_list(text):
    """'1,2,10-20' -> [1, 2, 10..20] in listed order. Empty string -> [].

    Duplicates are dropped, keeping the first occurrence. A 'lo-hi' range
    expands ascending (or descending if lo > hi).
    """
    ids = []
    seen = set()
    for part in re.split(r'[,;\s]+', text):
        if not part:
            continue
        if '-' in part:
            lo, hi = part.split('-', 1)
            lo, hi = int(lo), int(hi)
            chunk = range(lo, hi + 1) if lo <= hi else range(lo, hi - 1, -1)
        else:
            chunk = (int(part),)
        for i in chunk:
            if i not in seen:
                seen.add(i)
                ids.append(i)
    return ids


def as_ordered_ids(value):
    """Normalize a SELECTED_IDS entry or parse_id_list result to a de-duped list.

    None stays None. A set/frozenset has no sequence so it falls back to
    sorted(ids). A list/tuple keeps first-seen order.
    """
    if value is None:
        return None
    if isinstance(value, (set, frozenset)):
        return sorted(int(i) for i in value)
    ordered, seen = [], set()
    for i in value:
        i = int(i)
        if i not in seen:
            seen.add(i)
            ordered.append(i)
    return ordered


def parse_rewrite_map(text):
    """Parse shop-content rewrite rules.

    Supported forms (comma / whitespace separated):
      ShopItemId:NewPossessionId          -> rewrite ALL rows of that ShopItemId
      ShopItemId:OldPossessionId:NewId    -> rewrite only the row matching both

    Returns list of (shop_item_id, old_pid_or_None, new_pid).
    """
    rules = []
    for part in re.split(r'[,;\s]+', text or ''):
        if not part or ':' not in part:
            continue
        bits = part.split(':')
        if len(bits) == 2:
            rules.append((int(bits[0]), None, int(bits[1])))
        elif len(bits) == 3:
            rules.append((int(bits[0]), int(bits[1]), int(bits[2])))
    return rules


def encode_positive_int(n):
    """Encode a non-negative int the way C# MessagePack writes small integers."""
    if n <= 0x7f:
        return bytes([n])
    if n <= 0xff:
        return b'\xcc' + struct.pack('>B', n)
    if n <= 0xffff:
        return b'\xcd' + struct.pack('>H', n)
    if n <= 0xffffffff:
        return b'\xce' + struct.pack('>I', n)
    return b'\xcf' + struct.pack('>Q', n)


def patch_shop_item_content_possession(blob, rules):
    """Rewrite PossessionId (col 2) according to rewrite rules.

    rules: list of (shop_item_id, old_pid_or_None, new_pid)
      - old_pid is None  -> match any row with that ShopItemId
      - old_pid is int   -> match only the row with that exact PossessionId

    Returns (new_blob, rewritten_count, missing_rules).
    missing_rules lists rules that matched zero rows.
    Row is rebuilt when the msgpack encoding size of PossessionId changes
    (e.g. 7005 uint16 -> 242 fixint), so the client schema validator accepts it.
    """
    if not rules:
        return None, 0, []
    row_count, pos = read_array_len(blob, 0)
    out = bytearray(array_header(row_count))
    rewritten = 0
    matched = [False] * len(rules)
    for _ in range(row_count):
        col_count, p = read_array_len(blob, pos)
        col_pos = []
        cp = p
        for _ in range(col_count):
            col_pos.append(cp)
            cp = skip_msgpack_value(blob, cp)
        end = cp
        shop_item_id = read_int(blob, col_pos[0]) if col_count > 0 else None
        old_pid = read_int(blob, col_pos[2]) if col_count > 2 else None
        new_pid = None
        for i, (sid, want_old, nid) in enumerate(rules):
            if sid != shop_item_id:
                continue
            if want_old is not None and want_old != old_pid:
                continue
            new_pid = nid
            matched[i] = True
            break
        if new_pid is not None and col_count > 2:
            old_seg = bytes(blob[col_pos[2]:(col_pos[3] if col_count > 3 else end)])
            new_seg = encode_positive_int(new_pid)
            if old_seg == new_seg:
                out += blob[pos:end]
            else:
                new_row = bytearray(array_header(col_count))
                for ci in range(col_count):
                    seg_start = col_pos[ci]
                    seg_end = col_pos[ci + 1] if ci + 1 < col_count else end
                    if ci == 2:
                        new_row += new_seg
                    else:
                        new_row += bytes(blob[seg_start:seg_end])
                out += new_row
                rewritten += 1
        else:
            out += blob[pos:end]
        pos = end
    missing = [rules[i] for i, ok in enumerate(matched) if not ok]
    return bytes(out), rewritten, missing


def patch_shop_item_content_count(blob, rules):
    """Rewrite Count (col 4) according to rewrite rules.

    rules: list of (shop_item_id, old_count_or_None, new_count)
      - old_count is None -> match any row with that ShopItemId
      - old_count is int  -> match only the row with that exact Count

    Returns (new_blob, rewritten_count, missing_rules).
    """
    if not rules:
        return None, 0, []
    row_count, pos = read_array_len(blob, 0)
    out = bytearray(array_header(row_count))
    rewritten = 0
    matched = [False] * len(rules)
    for _ in range(row_count):
        col_count, p = read_array_len(blob, pos)
        col_pos = []
        cp = p
        for _ in range(col_count):
            col_pos.append(cp)
            cp = skip_msgpack_value(blob, cp)
        end = cp
        shop_item_id = read_int(blob, col_pos[0]) if col_count > 0 else None
        old_count = read_int(blob, col_pos[4]) if col_count > 4 else None
        new_count = None
        for i, (sid, want_old, ncount) in enumerate(rules):
            if sid != shop_item_id:
                continue
            if want_old is not None and want_old != old_count:
                continue
            new_count = ncount
            matched[i] = True
            break
        if new_count is not None and col_count > 4:
            old_seg = bytes(blob[col_pos[4]:end])
            new_seg = encode_positive_int(new_count)
            if old_seg == new_seg:
                out += blob[pos:end]
            else:
                new_row = bytearray(array_header(col_count))
                for ci in range(col_count):
                    seg_start = col_pos[ci]
                    seg_end = col_pos[ci + 1] if ci + 1 < col_count else end
                    if ci == 4:
                        new_row += new_seg
                    else:
                        new_row += bytes(blob[seg_start:seg_end])
                out += new_row
                rewritten += 1
        else:
            out += blob[pos:end]
        pos = end
    missing = [rules[i] for i, ok in enumerate(matched) if not ok]
    return bytes(out), rewritten, missing



def patch_shop_item_content_type(blob, rules):
    """Rewrite PossessionType (col 1) according to rewrite rules.

    rules: list of (shop_item_id, old_type_or_None, new_type)
      - old_type is None -> match any row with that ShopItemId
      - old_type is int  -> match only the row with that exact Count

    Returns (new_blob, rewritten_count, missing_rules).
    """
    if not rules:
        return None, 0, []
    row_count, pos = read_array_len(blob, 0)
    out = bytearray(array_header(row_count))
    rewritten = 0
    matched = [False] * len(rules)
    for _ in range(row_count):
        col_count, p = read_array_len(blob, pos)
        col_pos = []
        cp = p
        for _ in range(col_count):
            col_pos.append(cp)
            cp = skip_msgpack_value(blob, cp)
        end = cp
        shop_item_id = read_int(blob, col_pos[0]) if col_count > 0 else None
        old_type = read_int(blob, col_pos[1]) if col_count > 1 else None
        new_type = None
        for i, (sid, want_old, ntype) in enumerate(rules):
            if sid != shop_item_id:
                continue
            if want_old is not None and want_old != old_type:
                continue
            new_type = ntype
            matched[i] = True
            break
        if new_type is not None and col_count > 1:
            old_seg = bytes(blob[col_pos[1]:(col_pos[2] if col_count > 2 else end)])
            new_seg = encode_positive_int(new_type)
            if old_seg == new_seg:
                out += blob[pos:end]
            else:
                new_row = bytearray(array_header(col_count))
                for ci in range(col_count):
                    seg_start = col_pos[ci]
                    seg_end = col_pos[ci + 1] if ci + 1 < col_count else end
                    if ci == 1:
                        new_row += new_seg
                    else:
                        new_row += bytes(blob[seg_start:seg_end])
                out += new_row
                rewritten += 1
        else:
            out += blob[pos:end]
        pos = end
    missing = [rules[i] for i, ok in enumerate(matched) if not ok]
    return bytes(out), rewritten, missing


def array_header(n):
    if n <= 0x0f:     return bytes([0x90 | n])
    if n <= 0xffff:   return b'\xdc' + struct.pack('>H', n)
    return b'\xdd' + struct.pack('>I', n)


def reorder_blob(table, sort_cols, order_map, include=None):
    """Rebuild the table giving every row in order_map sort value = its rank.

    Only the sort columns are re-encoded (uint16); all other columns and all
    rows outside order_map are copied byte-for-byte. include(blob, col_pos)
    can restrict which rows participate (rows failing it are never rewritten).
    Ported from lunar-base's masterdata_bin._reorder_blob / the sort_*.py
    helpers — same encoding so the client schema validator accepts the blob.
    """
    n, pos = read_array_len(table, 0)
    out = bytearray(array_header(n))
    changed = 0
    for _ in range(n):
        col_count, p = read_array_len(table, pos)
        positions = []
        cp = p
        for _ in range(col_count):
            positions.append(cp)
            cp = skip_msgpack_value(table, cp)
        end = cp
        row_id = read_int(table, positions[0])
        if row_id in order_map and (include is None or include(table, positions)):
            enc = b'\xcd' + struct.pack('>H', order_map[row_id] & 0xffff)
            new_row = bytearray(array_header(col_count))
            for ci in range(col_count):
                seg = table[positions[ci]:(positions[ci + 1] if ci + 1 < col_count else end)]
                new_row += enc if ci in sort_cols else bytes(seg)
            out += new_row
            changed += 1
        else:
            out += table[pos:end]
        pos = end
    return bytes(out), changed


def ranks_from_list(ordered_ids, descending=False):
    """id -> rank. descending=True makes list[0] the highest value (SortOrderDesc)."""
    n = len(ordered_ids)
    if descending:
        return {rid: n - 1 - i for i, rid in enumerate(ordered_ids)}
    return {rid: i for i, rid in enumerate(ordered_ids)}


def patch_labyrinth_seasons(blob):
    """Leave exactly one within-period season per chapter — extras get End=0.

    The client's TryGetEventQuestLabyrinthWithinPeriod returns true only if
    EXACTLY ONE row passes IsWithinThePeriod; a second within-period row
    flips it false. Highest SeasonNumber per chapter wins.
    Columns: 0 ChapterId, 1 SeasonNumber, 2 StartDatetime, 3 EndDatetime.
    """
    rows = []
    row_count, pos = read_array_len(blob, 0)
    for _ in range(row_count):
        col_count, p = read_array_len(blob, pos)
        cp = p
        col_pos = []
        for _ in range(col_count):
            col_pos.append(cp)
            cp = skip_msgpack_value(blob, cp)
        rows.append((read_int(blob, col_pos[0]), read_int(blob, col_pos[1]),
                     col_pos[2], col_pos[3]))
        pos = cp

    max_season = {}
    for chapter, season, _, _ in rows:
        if season > max_season.get(chapter, -1):
            max_season[chapter] = season

    written = 0
    for chapter, season, start_pos, end_pos in rows:
        if blob[start_pos] != 0xd3 or blob[end_pos] != 0xd3:
            continue
        if season == max_season[chapter]:
            struct.pack_into('>q', blob, start_pos + 1, MIN_PATCH_MS)
            struct.pack_into('>q', blob, end_pos + 1, TARGET_END_MS)
        else:
            struct.pack_into('>q', blob, end_pos + 1, 0)
        written += 1
    return written


def patch_gimmick_sequence_schedules(blob):
    """Keep one active schedule per FirstGimmickSequenceId — extras get End=0.

    Multiple schedules per FirstSeqId render as overlapping GimmickOrnamentCage
    records and cancel each other. Lowest (StartDt, ScheduleId) is canonical
    (matches server's masterdata/gimmick.go dedup pick).
    Columns: 0 ScheduleId, 1 StartDt, 2 EndDt, 3 FirstSeqId.
    """
    rows = []
    row_count, pos = read_array_len(blob, 0)
    for _ in range(row_count):
        col_count, p = read_array_len(blob, pos)
        cp = p
        col_pos = []
        for _ in range(col_count):
            col_pos.append(cp)
            cp = skip_msgpack_value(blob, cp)
        sched_id  = read_int(blob, col_pos[0])
        start_dt  = struct.unpack('>q', blob[col_pos[1] + 1:col_pos[1] + 9])[0] if blob[col_pos[1]] == 0xd3 else 0
        first_seq = read_int(blob, col_pos[3])
        rows.append((first_seq, start_dt, sched_id, col_pos[2]))
        pos = cp

    canonical = {}
    for first_seq, start_dt, sched_id, _ in rows:
        cur = canonical.get(first_seq)
        if cur is None or (start_dt, sched_id) < cur:
            canonical[first_seq] = (start_dt, sched_id)

    zeroed = 0
    for first_seq, start_dt, sched_id, end_pos in rows:
        if (start_dt, sched_id) == canonical[first_seq]:
            continue
        if blob[end_pos] != 0xd3:
            continue
        struct.pack_into('>q', blob, end_pos + 1, 0)
        zeroed += 1
    return zeroed


def patch_wolf_chapter_battle_point(blob):
    """Chapter 314 ("Variation: Blazing Blossom") side-quests reference
    a BattlePointIndex that doesn't exist in the corresponding battle
    field locale asset, NRE'ing the client's
    TurnBattlePrefabAssetLoadApi.CreateFieldAssetLoadPlan during battle
    setup. The locale (bt_field_locale_eq000004_02) only has BattlePoints
    1-5, but BG 1880-1889 row col 6 says 8 — and the only BattlePoint
    whose _battleFieldPrefabIndex is 8 has _battlePointIndex 5, so 5 is
    the intended value (single-column-slip pattern).
    Idempotent: only rewrites col 6 when it's still 8.
    Columns: 0 BattleGroupId, 1 WaveNumber, 2 BattleId, 3 WaveStartActAssetId,
             4 WaveEndActAssetId, 5 BattleCameraControllerAssetId,
             6 BattlePointIndex, 7 BattleStartCameraType.
    """
    row_count, pos = read_array_len(blob, 0)
    patched = 0
    for _ in range(row_count):
        col_count, p = read_array_len(blob, pos)
        cp = p
        col_pos = []
        for _ in range(col_count):
            col_pos.append(cp)
            cp = skip_msgpack_value(blob, cp)
        bg_id = read_int(blob, col_pos[0])
        if 1880 <= bg_id <= 1889 and col_count > 6 and blob[col_pos[6]] == 0x08:
            # BattlePointIndex is a positive fixint (single byte 0x00-0x7F);
            # 8 → 5 is just a byte swap, no length recompute.
            blob[col_pos[6]] = 0x05
            patched += 1
        pos = cp
    return patched


def _subsumes(broad, narrow, family):
    """True if every entity/quest matching narrow targets also matches broad.

    broad/narrow are sorted tuples of (TargetType, TargetValue).
    Used by patch_campaign_dedup to drop redundant narrower-scope banners when
    a broader-scope row with the same effect+value already covers them.
    """
    broad_types = {t for t, _ in broad}
    if family == 'quest':
        if 1 in broad_types:                          # WHOLE_QUEST subsumes everything
            return True
        broad_qts = {v for t, v in broad if t == 2}   # QUEST_TYPE values present in broad
        if not broad_qts:
            return False
        for nt, nv in narrow:
            if nt == 1:                               # WHOLE only subsumes itself
                return False
            if nt == 2:                               # narrow QUEST_TYPE=V → broad must list V too
                if nv not in broad_qts: return False
            elif nt in (3, 6, 7):                     # event-side narrow → broad must cover EVENT
                if 2 not in broad_qts: return False
            elif nt in (4, 5):                        # main-side narrow → broad must cover MAIN
                if 1 not in broad_qts: return False
            else:
                return False
        return True
    if family == 'enhance':
        # *_ALL covers its sibling per-id / per-category target types.
        all_map = {1: {11, 12, 13}, 2: {21, 22, 23}, 3: {31, 32}}
        for nt, _ in narrow:
            covered_by_all = any(at in broad_types and nt in children
                                 for at, children in all_map.items())
            if not covered_by_all and nt not in broad_types:
                return False
        return True
    return False


def patch_campaign_dedup(camp_blob, target_rows, effect_rows, cfg, now_ms):
    """Dedup-extend a campaign table: pick one baseline-value rerun per
    (effect, target) tuple, drop entity-specific rows entirely, then drop
    any pick subsumed by another pick with the same effect+value+payload.
    """
    rows = msgpack.unpackb(bytes(camp_blob), raw=True)

    targets_by_group = {}
    for tg in target_rows:
        targets_by_group.setdefault(tg[0], []).append((tg[2], tg[3]))

    effects_by_id = None
    if effect_rows is not None:
        effects_by_id = {e[0]: (e[1], e[2], e[3]) for e in effect_rows}

    groups = {}      # key -> [(eff_val, camp_id, row_idx), ...] for reruns
    permanent = {}   # key -> (eff_val, target_tuple) for already-active-permanent rows
    for idx, row in enumerate(rows):
        if row[cfg['user_status_col']] != 1:
            continue
        targets = targets_by_group.get(row[cfg['tg_col']], [])
        if not targets or any(t[0] in cfg['entity_id_targets'] for t in targets):
            continue
        if effects_by_id is not None:
            eff = effects_by_id.get(row[cfg['eff_group_col']])
            if eff is None:
                continue
            eff_type, eff_val, item_group_id = eff
            extra = (item_group_id,)
        else:
            eff_type = row[cfg['eff_type_col']]
            eff_val  = row[cfg['eff_val_col']]
            extra = ()
        target_tuple = tuple(sorted(targets))
        key = (eff_type, target_tuple) + extra
        start_dt = row[cfg['start_col']]
        end_dt   = row[cfg['end_col']]
        if start_dt <= now_ms and end_dt >= MAX_PATCH_MS:
            permanent[key] = (eff_val, target_tuple)
        elif end_dt < MAX_PATCH_MS:
            groups.setdefault(key, []).append((eff_val, row[cfg['id_col']], idx))

    # Pass A: per key, pick the smallest-value rerun — but skip keys already
    # delivered by a permanent row (re-run idempotence).
    baseline = {}   # key -> (pick_value, pick_idx, target_tuple)
    for k, candidates in groups.items():
        if k in permanent:
            continue
        val, _, idx = min(candidates)
        baseline[k] = (val, idx, k[1])

    # Pass B: drop any pick subsumed by another permanent row OR baseline pick
    # in the same (effect, value [, item_group]) bucket.
    family = cfg['family']
    all_effective = list(permanent.items()) + [(k, (v, t)) for k, (v, _, t) in baseline.items()]
    picks = set()
    for k, (val, idx, targets) in baseline.items():
        bucket = (k[0], val) + k[2:]
        subsumed = False
        for k2, (val2, targets2) in all_effective:
            if k2 == k:
                continue
            if (k2[0], val2) + k2[2:] != bucket:
                continue
            if targets2 != targets and _subsumes(targets2, targets, family):
                subsumed = True
                break
        if not subsumed:
            picks.add(idx)

    row_count, pos = read_array_len(camp_blob, 0)
    end_col = cfg['end_col']
    bumped = 0
    for idx in range(row_count):
        col_count, p = read_array_len(camp_blob, pos)
        for ci in range(col_count):
            if ci == end_col and idx in picks and camp_blob[p] == 0xd3:
                struct.pack_into('>q', camp_blob, p + 1, TARGET_END_MS)
                bumped += 1
            p = skip_msgpack_value(camp_blob, p)
        pos = p
    return bumped


# --- Per-table apply helper ---

def apply_to_table(toc, data_blob, new_blobs, name, mutator):
    """Decompress name's blob (preferring new_blobs if already touched), run
    mutator(bytearray) → result, repack back into new_blobs. Returns mutator's
    return value or None if the table is absent.
    """
    if name not in toc:
        return None
    if name in new_blobs:
        src = bytes(new_blobs[name])
    else:
        offset, length = toc[name]
        src = data_blob[offset:offset + length]
    unpacked = msgpack.unpackb(src, raw=True)
    compressed = isinstance(unpacked, msgpack.ExtType) and unpacked.code == 99
    if compressed:
        unc_len, lz4_data = read_lz4_ext_header(unpacked.data)
        table = bytearray(lz4.block.decompress(lz4_data, uncompressed_size=unc_len))
    else:
        table = bytearray(src)
    result = mutator(table)
    if result is None and not compressed:
        # add_table_rows returns None to skip; preserve original bytes.
        return None
    if isinstance(result, (bytes, bytearray)):
        # Caller returned a fresh blob (add_table_rows); use it directly.
        new_blobs[name] = build_lz4_ext_blob(bytes(result)) if compressed else bytes(result)
        return True
    new_blobs[name] = build_lz4_ext_blob(bytes(table)) if compressed else bytes(table)
    return result


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="Patch master data timestamps to extend content to 2030.")
    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument("--key", default=DEFAULT_KEY, help="AES key as hex (default: built-in)")
    key_group.add_argument("--key-file", help="Raw key file (16 or 32 bytes)")
    iv_group = parser.add_mutually_exclusive_group()
    iv_group.add_argument("--iv", default=DEFAULT_IV, help="AES IV as hex (default: built-in)")
    iv_group.add_argument("--iv-file", help="Raw IV file (16 bytes)")
    parser.add_argument("--input", default=DEFAULT_INPUT, help=f"Input .bin.e (default: {DEFAULT_INPUT})")
    parser.add_argument("--output", help="Output .bin.e (default: overwrite input)")
    parser.add_argument("--dry-run", action="store_true", help="Decrypt + patch but don't write")
    parser.add_argument("--event-quests", nargs="?", const="", default=None, metavar="IDS",
                        help="Event quest chapter ids to keep visible, in display order (e.g. '1,2,10-20'); empty string hides all; overrides SELECTED_IDS")
    parser.add_argument("--banners", nargs="?", const="", default=None, metavar="IDS",
                        help="Gacha banner (MomBannerId) ids to keep visible, in display order; empty string hides all; overrides SELECTED_IDS")
    parser.add_argument("--premium-shops", nargs="?", const="", default=None, metavar="IDS",
                        help="Premium shop ids (ShopGroupType=1) to keep visible, in display order; empty string hides all; overrides SELECTED_IDS")
    parser.add_argument("--exchange-shops", nargs="?", const="", default=None, metavar="IDS",
                        help="Exchange shop ids (ShopGroupType=4) to keep visible, in display order; empty string hides all; overrides SELECTED_IDS")
    parser.add_argument("--exclude-consumables", nargs="?", const="", default=None, metavar="IDS",
                        help="Consumable item ids whose EndDatetime is left unchanged (e.g. '3007-3116,1007'); empty / omitted excludes none")
    parser.add_argument("--rewrite-shop-content", nargs="?", const="", default=None, metavar="MAP",
                        help="Rewrite m_shop_item_content_possession PossessionId. "
                             "Forms: ShopItemId:NewId (all rows) or ShopItemId:OldId:NewId (one row). "
                             "Example: '609705:46,600705:7005:242'")
    parser.add_argument("--rewrite-shop-count", nargs="?", const="", default=None, metavar="MAP",
                        help="Rewrite m_shop_item_content_possession Count. "
                             "Forms: ShopItemId:NewCount (all rows) or ShopItemId:OldCount:NewCount (one row). "
                             "Example: '140355:3060:0'")
    parser.add_argument("--rewrite-shop-type", nargs="?", const="", default=None, metavar="MAP",
                        help="Rewrite m_shop_item_content_possession PossessionType. "
                             "Forms: ShopItemId:NewType (all rows) or ShopItemId:OldType:NewType (one row). "
                             "Example: '140355:11:6'")
    args = parser.parse_args()

    key = open(args.key_file, "rb").read() if args.key_file else bytes.fromhex(args.key)
    if len(key) not in (16, 32):
        sys.exit(f"ERROR: AES key must be 16 or 32 bytes, got {len(key)}")
    iv = open(args.iv_file, "rb").read() if args.iv_file else bytes.fromhex(args.iv)
    if len(iv) != 16:
        sys.exit(f"ERROR: AES IV must be 16 bytes, got {len(iv)}")
    aes_bits = len(key) * 8
    output_path = args.output or args.input

    print(f"Reading {args.input}...")
    with open(args.input, "rb") as f:
        encrypted = f.read()
    print(f"  Encrypted size: {len(encrypted)} bytes")

    print(f"Decrypting (AES-{aes_bits}-CBC)...")
    try:
        decrypted = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted), AES.block_size)
    except ValueError as e:
        sys.exit(f"ERROR: Decryption failed: {e}\n  Check that the key and IV are correct.")
    print(f"  Decrypted size: {len(decrypted)} bytes")

    print("Parsing MasterMemory header...")
    try:
        toc = msgpack.unpackb(decrypted, raw=False, strict_map_key=False)
        data_blob = b""
    except msgpack.ExtraData as e:
        toc = e.unpacked
        data_blob = e.extra
    if not isinstance(toc, dict):
        sys.exit(f"ERROR: Expected dict header, got {type(toc).__name__}")
    print(f"  {len(toc)} tables, data blob: {len(data_blob)} bytes")

    print(f"\nPatching EndDatetime fields (target: {TARGET_END_DT.isoformat()})...")

    # Effective per-id selections: CLI flags override the in-file SELECTED_IDS.
    # selection_order keeps listed order for sort-column rewrite; selections
    # is the matching set used for extend/expire membership tests.
    selection_order = {}
    selections = {}
    for cat, cli_val in (('event_quests', args.event_quests),
                         ('banners', args.banners),
                         ('premium_shops', args.premium_shops),
                         ('exchange_shops', args.exchange_shops)):
        raw = parse_id_list(cli_val) if cli_val is not None else SELECTED_IDS[cat]
        ordered = as_ordered_ids(raw)
        selection_order[cat] = ordered
        selections[cat] = None if ordered is None else set(ordered)

    # Consumable EndDatetime exclusions come only from --exclude-consumables.
    # Empty / omitted flag -> exclude nothing (bump every m_consumable_item_term row).
    #
    # The client often resolves the term row via m_consumable_item col4 (a term
    # ref that may differ from ConsumableItemId — e.g. item 6004 -> term 21).
    # So for every listed item id we also exclude that term-ref id.
    excluded_item_ids = frozenset(parse_id_list(args.exclude_consumables or ""))
    excluded_consumables = set(excluded_item_ids)  # term-table PKs to leave untouched
    term_ref_resolved = {}  # item_id -> term_ref (col4) when it differs
    if excluded_item_ids:
        item_rows = _load_decoded_table(toc, data_blob, 'm_consumable_item')
        if item_rows is not None:
            by_item = {r[0]: r for r in item_rows}
            for iid in excluded_item_ids:
                row = by_item.get(iid)
                if row is None or len(row) <= 4:
                    continue
                term_ref = int(row[4])
                excluded_consumables.add(term_ref)
                if term_ref != iid:
                    term_ref_resolved[iid] = term_ref
        else:
            print("  WARNING: m_consumable_item not in TOC, cannot resolve term refs")
    excluded_consumables = frozenset(excluded_consumables)
    table_exclude_ids = {}
    if excluded_consumables:
        table_exclude_ids['m_consumable_item_term'] = (0, excluded_consumables)
    print(f"  Consumable exclusions: {len(excluded_item_ids)} item id(s) -> "
          f"{len(excluded_consumables)} term id(s)"
          f"{' (CLI --exclude-consumables)' if args.exclude_consumables is not None else ' (none — flag omitted)'}")
    if term_ref_resolved:
        preview = ", ".join(f"{i}->{t}" for i, t in sorted(term_ref_resolved.items())[:12])
        more = f" (+{len(term_ref_resolved) - 12} more)" if len(term_ref_resolved) > 12 else ""
        print(f"    term-ref redirects (item->term): {preview}{more}")

    # Tables routed to patch_managed_table() instead of the blanket bump.
    # m_mom_banner is always managed: non-gacha ad banners are force-expired
    # even when no banner selection is configured.
    managed_tables = {'m_mom_banner'}
    if selections['event_quests'] is not None:
        managed_tables.add('m_event_quest_chapter')
    if selections['premium_shops'] is not None or selections['exchange_shops'] is not None:
        managed_tables.add('m_shop')

    new_blobs = {}
    stats = {}
    total_patched = 0
    for tname, columns in PATCH_COLUMNS.items():
        if tname in SKIP_TABLES or tname in managed_tables:
            continue
        col_indices = {idx for idx, _ in columns}
        row_filter = TABLE_PATCH_FILTERS.get(tname)
        exclude = table_exclude_ids.get(tname)
        result = apply_to_table(toc, data_blob, new_blobs, tname,
                                lambda b: patch_table_blob(b, col_indices, row_filter, exclude))
        if result is None:
            continue
        count, skip_count, excl_count = result
        if count > 0:
            stats[tname] = (count, skip_count, excl_count)
            total_patched += count
        else:
            # No patchable rows — undo the (no-op) repack so file output stays minimal.
            del new_blobs[tname]

    print(f"\n  Patched {total_patched} values across {len(stats)} tables:")
    for tname in sorted(stats):
        count, skip_count, excl_count = stats[tname]
        cols = ", ".join(name for _, name in PATCH_COLUMNS[tname])
        suffix = f" (skipped {skip_count} rows by filter)" if skip_count else ""
        suffix += f" (kept {excl_count} rows excluded)" if excl_count else ""
        print(f"    {tname}: {count} values ({cols}){suffix}")

    # --- Per-ID selection passes ---
    now_ms = int(datetime.now(tz=timezone.utc).timestamp() * 1000)

    def apply_managed(table, end_col, start_col, classify, owners):
        result = apply_to_table(toc, data_blob, new_blobs, table,
                                lambda b: patch_managed_table(b, end_col, start_col, classify, now_ms))
        if result is None:
            print(f"  WARNING: {table} not in TOC, skipping selection")
            return
        extended, expired, bumped, starts, found = result
        if extended == expired == bumped == starts == 0:
            # Nothing changed — undo the repack so output stays minimal.
            del new_blobs[table]
        parts = [f"extended {extended}", f"expired {expired}"]
        if bumped:
            parts.append(f"blanket-bumped {bumped} out-of-scope rows")
        if starts:
            parts.append(f"pulled {starts} future starts into the past")
        print(f"\n  {table}: {', '.join(parts)}")
        for owner in owners:
            sel = selections[owner]
            if sel is None:
                continue
            missing = sorted(sel - found.get(owner, set()))
            if missing:
                shown = ", ".join(str(i) for i in missing[:20])
                more = f" (+{len(missing) - 20} more)" if len(missing) > 20 else ""
                print(f"    WARNING: {owner}: ids not found in {table}: {shown}{more}")

    if selections['event_quests'] is not None:
        apply_managed('m_event_quest_chapter', 9, 8,
                      classify_event_quest(selections['event_quests']),
                      ['event_quests'])
    apply_managed('m_mom_banner', 7, 6,
                  classify_banner(selections['banners']),
                  ['banners'])
    if 'm_shop' in managed_tables:
        apply_managed('m_shop', 10, 9,
                      classify_shop(selections['premium_shops'], selections['exchange_shops']),
                      ['premium_shops', 'exchange_shops'])

    # --- List-order sort (CLI / SELECTED_IDS sequence, not alphabetical) ---
    def apply_list_order(table, sort_cols, ordered_ids, include=None, descending=False):
        if not ordered_ids:
            return
        order_map = ranks_from_list(ordered_ids, descending=descending)
        changed_box = [0]

        def mutator(blob):
            new_blob, changed = reorder_blob(blob, sort_cols, order_map, include)
            changed_box[0] = changed
            return new_blob if changed else 0

        result = apply_to_table(toc, data_blob, new_blobs, table, mutator)
        if result is None:
            print(f"  WARNING: {table} not in TOC, skipping list-order sort")
            return
        preview = ", ".join(str(i) for i in ordered_ids[:8])
        more = f", ... (+{len(ordered_ids) - 8} more)" if len(ordered_ids) > 8 else ""
        direction = "SortOrderDesc, high-first" if descending else "low-first"
        print(f"\n  {table}: reordered {changed_box[0]} rows by list order "
              f"({direction}): {preview}{more}")

    def is_gacha_banner(blob, col_pos):
        return read_int(blob, col_pos[2]) == BANNER_DOMAIN_GACHA

    if selection_order['event_quests']:
        apply_list_order('m_event_quest_chapter', {2, 10},
                         selection_order['event_quests'])
    if selection_order['banners']:
        # SortOrderDesc: client shows higher values first, so invert ranks
        # so the first id in the bat/CLI list is the one on screen first.
        apply_list_order('m_mom_banner', {1},
                         selection_order['banners'],
                         include=is_gacha_banner, descending=False)
    shop_map = {}
    if selection_order['premium_shops']:
        for rank, rid in enumerate(selection_order['premium_shops']):
            shop_map[rid] = rank
    if selection_order['exchange_shops']:
        for rank, rid in enumerate(selection_order['exchange_shops']):
            shop_map[rid] = rank
    if shop_map:
        # Premium and exchange ranks restart at 0 independently, so we cannot
        # use a single ranks_from_list; pass the merged map via a wrapper.
        changed_box = [0]

        def mutator(blob, _map=shop_map):
            new_blob, changed = reorder_blob(blob, {2}, _map)
            changed_box[0] = changed
            return new_blob if changed else 0

        result = apply_to_table(toc, data_blob, new_blobs, 'm_shop', mutator)
        if result is None:
            print("  WARNING: m_shop not in TOC, skipping list-order sort")
        else:
            n_p = len(selection_order['premium_shops'] or ())
            n_e = len(selection_order['exchange_shops'] or ())
            print(f"\n  m_shop: reordered {changed_box[0]} rows by list order "
                  f"(premium {n_p}, exchange {n_e}, ranks restart per group)")

    # --- Ad/promo tables: force-expired (news cut-ins, login banner popup) ---
    for tname, end_col in EXPIRED_AD_TABLES.items():
        result = apply_to_table(toc, data_blob, new_blobs, tname,
                                lambda b, ec=end_col: expire_table_end(b, ec))
        if result is None:
            print(f"  WARNING: {tname} not in TOC, skipping ad expire")
            continue
        if result == 0:
            # Already fully expired — undo the (no-op) repack.
            del new_blobs[tname]
        print(f"\n  {tname}: {result} ad rows force-expired (hidden)")

    emptied = []
    for tname in sorted(EMPTY_TABLES):
        if tname in toc:
            new_blobs[tname] = msgpack.packb([], use_bin_type=True)
            emptied.append(tname)
    if emptied:
        print(f"\n  Emptied tables: {', '.join(emptied)}")
    if SKIP_TABLES:
        print(f"\n  Skipped tables: {', '.join(sorted(SKIP_TABLES))}")

    added = []
    for tname, rows in TABLE_ROW_ADDITIONS.items():
        result = apply_to_table(toc, data_blob, new_blobs, tname,
                                lambda b, _rows=rows: add_table_rows(b, _rows))
        if result is None:
            print(f"  {tname}: not in TOC or row(s) already present, skipping")
        else:
            added.append(f"{tname} (+{len(rows)} row)")
    if added:
        print(f"\n  Added rows: {', '.join(added)}")

    # If an excluded item has neither its own term row nor a term-ref (col4)
    # row, the client treats it as permanent. Inject an expired term keyed by
    # the item id as a fallback. Dates use int64 (0xd3) like the rest of the
    # table — msgpack.packb would use a tighter encoding the client rejects.
    if excluded_item_ids:
        existing = set()
        loaded = _load_decoded_table(toc, data_blob, 'm_consumable_item_term')
        if loaded is not None:
            if 'm_consumable_item_term' in new_blobs:
                src = new_blobs['m_consumable_item_term']
                unpacked = msgpack.unpackb(src, raw=True)
                if isinstance(unpacked, msgpack.ExtType) and unpacked.code == 99:
                    unc_len, lz4_data = read_lz4_ext_header(unpacked.data)
                    raw = lz4.block.decompress(lz4_data, uncompressed_size=unc_len)
                    loaded = msgpack.unpackb(raw, raw=True)
                else:
                    loaded = unpacked
            existing = {r[0] for r in loaded}
        # Only inject when the item has no usable term (self id or col4 ref).
        missing_ids = []
        for iid in sorted(excluded_item_ids):
            term_ref = term_ref_resolved.get(iid, iid)
            if iid not in existing and term_ref not in existing:
                missing_ids.append(iid)
        if missing_ids:
            def encode_term_row(item_id, start_ms, end_ms):
                # array of 3: id (compact), start int64, end int64
                return (array_header(3)
                        + encode_positive_int(item_id)
                        + b'\xd3' + struct.pack('>q', start_ms)
                        + b'\xd3' + struct.pack('>q', end_ms))

            def inject_expired_terms_sorted(blob, _ids=missing_ids):
                """Insert missing exclude ids as expired terms and keep the
                table sorted by ConsumableItemId (MasterMemory binary search)."""
                count, pos = read_array_len(blob, 0)
                by_id = {}
                p = pos
                for _ in range(count):
                    col_count, rp = read_array_len(blob, p)
                    rid = read_int(blob, rp)
                    end = skip_msgpack_value(blob, p)
                    by_id[rid] = bytes(blob[p:end])
                    p = end
                added = 0
                for i in _ids:
                    if i not in by_id:
                        by_id[i] = encode_term_row(
                            i,
                            1637287200000,  # 2021-11-19 02:00:00 UTC (same style as real tickets)
                            1638496799000,  # 2021-12-03 01:59:59 UTC
                        )
                        added += 1
                if added == 0:
                    return None
                ordered_ids = sorted(by_id)
                out = bytearray(array_header(len(ordered_ids)))
                for rid in ordered_ids:
                    out += by_id[rid]
                inject_expired_terms_sorted.added = added
                return bytes(out)

            inject_expired_terms_sorted.added = 0
            result = apply_to_table(toc, data_blob, new_blobs, 'm_consumable_item_term',
                                    inject_expired_terms_sorted)
            if result is None:
                print(f"\n  m_consumable_item_term: could not inject expired rows for "
                      f"{len(missing_ids)} missing exclude id(s)")
            else:
                n = inject_expired_terms_sorted.added
                preview = ", ".join(str(i) for i in missing_ids[:12])
                more = f" (+{len(missing_ids) - 12} more)" if len(missing_ids) > 12 else ""
                print(f"\n  m_consumable_item_term: injected {n} expired term row(s), "
                      f"table re-sorted, for: {preview}{more}")

    zeroed = apply_to_table(toc, data_blob, new_blobs, 'm_gimmick_sequence_schedule',
                            patch_gimmick_sequence_schedules)
    if zeroed is None:
        print("  WARNING: m_gimmick_sequence_schedule not in TOC, skipping")
    else:
        print(f"\n  Gimmick sequence schedules: {zeroed} duplicate rows expired (1 active per FirstGimmickSequenceId)")

    for family, cfg in CAMPAIGN_CFG.items():
        camp_table = f'm_{family}_campaign'
        if camp_table not in toc or cfg['target_table'] not in toc:
            print(f"  WARNING: {camp_table} / {cfg['target_table']} not in TOC, skipping dedup")
            continue
        target_rows  = _load_decoded_table(toc, data_blob, cfg['target_table'])
        effect_rows  = _load_decoded_table(toc, data_blob, cfg['effect_table']) if cfg['effect_table'] else None
        if cfg['effect_table'] and effect_rows is None:
            print(f"  WARNING: {cfg['effect_table']} not in TOC, skipping {family} dedup")
            continue
        bumped = apply_to_table(toc, data_blob, new_blobs, camp_table,
                                lambda b, t=target_rows, e=effect_rows: patch_campaign_dedup(b, t, e, cfg, now_ms))
        print(f"\n  {camp_table}: dedup-extended {bumped} rows (baseline-value per unique (effect, target))")

    written = apply_to_table(toc, data_blob, new_blobs, 'm_event_quest_labyrinth_season',
                             patch_labyrinth_seasons)
    if written is None:
        print("  WARNING: m_event_quest_labyrinth_season not in TOC, skipping")
    else:
        print(f"\n  Labyrinth seasons: {written} rows windowed (1 active per chapter)")

    bp_fixed = apply_to_table(toc, data_blob, new_blobs, 'm_battle_group',
                              patch_wolf_chapter_battle_point)
    if bp_fixed is None:
        print("  WARNING: m_battle_group not in TOC, skipping wolf-chapter fix")
    else:
        print(f"\n  Wolf chapter (314) BattlePointIndex: {bp_fixed} rows corrected 8->5 (BG 1880-1889)")

    # --- Optional PossessionId rewrites in shop item content ---
    rewrite_rules = parse_rewrite_map(args.rewrite_shop_content or "")
    if rewrite_rules:
        def mutator(blob, _rules=rewrite_rules):
            new_blob, rewritten, missing = patch_shop_item_content_possession(blob, _rules)
            mutator.result = (rewritten, missing)
            return new_blob if rewritten else 0

        mutator.result = (0, [])
        result = apply_to_table(toc, data_blob, new_blobs, 'm_shop_item_content_possession', mutator)
        if result is None:
            print("  WARNING: m_shop_item_content_possession not in TOC, skipping content rewrite")
        else:
            rewritten, missing = mutator.result
            print(f"\n  m_shop_item_content_possession: rewrote PossessionId on {rewritten} row(s)")
            if missing:
                def fmt(r):
                    sid, old, new = r
                    return f"{sid}:{old}:{new}" if old is not None else f"{sid}:{new}"
                print(f"    WARNING: rule(s) matched nothing: {', '.join(fmt(r) for r in missing)}")

    count_rules = parse_rewrite_map(args.rewrite_shop_count or "")
    if count_rules:
        def mutator_count(blob, _rules=count_rules):
            new_blob, rewritten, missing = patch_shop_item_content_count(blob, _rules)
            mutator_count.result = (rewritten, missing)
            return new_blob if rewritten else 0

        mutator_count.result = (0, [])
        result = apply_to_table(toc, data_blob, new_blobs, 'm_shop_item_content_possession', mutator_count)
        if result is None:
            print("  WARNING: m_shop_item_content_possession not in TOC, skipping count rewrite")
        else:
            rewritten, missing = mutator_count.result
            print(f"\n  m_shop_item_content_possession: rewrote Count on {rewritten} row(s)")
            if missing:
                def fmt(r):
                    sid, old, new = r
                    return f"{sid}:{old}:{new}" if old is not None else f"{sid}:{new}"
                print(f"    WARNING: rule(s) matched nothing: {', '.join(fmt(r) for r in missing)}")

    type_rules = parse_rewrite_map(args.rewrite_shop_type or "")
    if type_rules:
        def mutator_type(blob, _rules=type_rules):
            new_blob, rewritten, missing = patch_shop_item_content_type(blob, _rules)
            mutator_type.result = (rewritten, missing)
            return new_blob if rewritten else 0

        mutator_type.result = (0, [])
        result = apply_to_table(toc, data_blob, new_blobs, 'm_shop_item_content_possession', mutator_type)
        if result is None:
            print("  WARNING: m_shop_item_content_possession not in TOC, skipping type rewrite")
        else:
            rewritten, missing = mutator_type.result
            print(f"\n  m_shop_item_content_possession: rewrote PossessionType on {rewritten} row(s)")
            if missing:
                def fmt(r):
                    sid, old, new = r
                    return f"{sid}:{old}:{new}" if old is not None else f"{sid}:{new}"
                print(f"    WARNING: rule(s) matched nothing: {', '.join(fmt(r) for r in missing)}")

    if args.dry_run:
        print("\n[DRY RUN] Skipping rebuild and encryption.")
        return

    print("\nRebuilding MasterMemory binary...")
    sorted_tables = sorted(toc.items(), key=lambda kv: kv[1][0])
    new_toc = {}
    blob_parts = []
    current_offset = 0
    for tname, (orig_offset, orig_length) in sorted_tables:
        part = new_blobs[tname] if tname in new_blobs else data_blob[orig_offset:orig_offset + orig_length]
        new_toc[tname] = (current_offset, len(part))
        blob_parts.append(part)
        current_offset += len(part)
    new_data_blob = b''.join(blob_parts)
    new_header = msgpack.packb(new_toc, use_bin_type=True)
    new_decrypted = new_header + new_data_blob
    print(f"  Header: {len(new_header)} bytes, blob: {len(new_data_blob)} bytes")
    print(f"  Total: {len(new_decrypted)} bytes (original: {len(decrypted)})")

    print(f"Re-encrypting (AES-{aes_bits}-CBC)...")
    re_encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(new_decrypted, AES.block_size))
    print(f"  Re-encrypted size: {len(re_encrypted)} bytes")

    print(f"Writing {output_path}...")
    with open(output_path, "wb") as f:
        f.write(re_encrypted)
    print(f"  Done! Patched binary written to {output_path}")


def _load_decoded_table(toc, data_blob, name):
    """Decompress + msgpack-decode a table; returns the list of rows (each a list of column values)."""
    if name not in toc:
        return None
    offset, length = toc[name]
    src = data_blob[offset:offset + length]
    unpacked = msgpack.unpackb(src, raw=True)
    if isinstance(unpacked, msgpack.ExtType) and unpacked.code == 99:
        unc_len, lz4_data = read_lz4_ext_header(unpacked.data)
        raw = lz4.block.decompress(lz4_data, uncompressed_size=unc_len)
        return msgpack.unpackb(raw, raw=True)
    return unpacked


if __name__ == "__main__":
    main()
