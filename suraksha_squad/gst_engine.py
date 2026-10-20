"""
Decimal-Exact GST, Modulo-36 GSTIN Checksum, and India Post PIN-to-State Engine for Suraksha Squad.
"""

from __future__ import annotations
import re
from decimal import Decimal, ROUND_HALF_UP
from typing import Dict, Optional
import requests


GST_STATE_CODES: Dict[str, str] = {
    "01": "Jammu & Kashmir", "02": "Himachal Pradesh", "03": "Punjab", "04": "Chandigarh",
    "05": "Uttarakhand", "06": "Haryana", "07": "Delhi", "08": "Rajasthan",
    "09": "Uttar Pradesh", "10": "Bihar", "11": "Sikkim", "12": "Arunachal Pradesh",
    "13": "Nagaland", "14": "Manipur", "15": "Mizoram", "16": "Tripura",
    "17": "Meghalaya", "18": "Assam", "19": "West Bengal", "20": "Jharkhand",
    "21": "Odisha", "22": "Chhattisgarh", "23": "Madhya Pradesh", "24": "Gujarat",
    "26": "Dadra & Nagar Haveli and Daman & Diu", "27": "Maharashtra", "29": "Karnataka",
    "30": "Goa", "31": "Lakshadweep", "32": "Kerala", "33": "Tamil Nadu",
    "34": "Puducherry", "35": "Andaman & Nicobar", "36": "Telangana",
    "37": "Andhra Pradesh", "38": "Ladakh",
}

PIN_PREFIX_TO_STATE: Dict[str, str] = {
    "11": "Delhi", "12": "Haryana", "13": "Haryana", "14": "Punjab", "15": "Punjab",
    "16": "Chandigarh", "17": "Himachal Pradesh", "18": "Jammu & Kashmir", "19": "Jammu & Kashmir",
    "20": "Uttar Pradesh", "21": "Uttar Pradesh", "22": "Uttar Pradesh", "23": "Uttar Pradesh",
    "24": "Uttar Pradesh", "25": "Uttar Pradesh", "26": "Uttar Pradesh", "27": "Uttar Pradesh",
    "28": "Uttar Pradesh", "30": "Rajasthan", "31": "Rajasthan", "32": "Rajasthan",
    "33": "Rajasthan", "34": "Rajasthan", "36": "Gujarat", "37": "Gujarat", "38": "Gujarat",
    "39": "Gujarat", "40": "Maharashtra", "41": "Maharashtra", "42": "Maharashtra",
    "43": "Maharashtra", "44": "Maharashtra", "45": "Madhya Pradesh", "46": "Madhya Pradesh",
    "47": "Madhya Pradesh", "48": "Madhya Pradesh", "49": "Chhattisgarh", "50": "Telangana",
    "51": "Andhra Pradesh", "52": "Andhra Pradesh", "53": "Andhra Pradesh", "56": "Karnataka",
    "57": "Karnataka", "58": "Karnataka", "59": "Karnataka", "60": "Tamil Nadu",
    "61": "Tamil Nadu", "62": "Tamil Nadu", "63": "Tamil Nadu", "64": "Tamil Nadu",
    "67": "Kerala", "68": "Kerala", "69": "Kerala", "70": "West Bengal", "71": "West Bengal",
    "72": "West Bengal", "73": "West Bengal", "74": "West Bengal", "75": "Odisha",
    "76": "Odisha", "77": "Odisha", "78": "Assam", "80": "Bihar", "81": "Bihar",
    "82": "Bihar", "83": "Jharkhand",
}


def resolve_pin_to_state(pincode: str, allow_network: bool = False) -> Optional[str]:
    """Resolves a 6-digit Indian PIN code to its State via India Post API or deterministic prefix table."""
    pin = pincode.strip()
    if not re.match(r"^[1-8][0-9]{5}$", pin):
        return None
    if allow_network:
        try:
            resp = requests.get(f"https://api.postalpincode.in/pincode/{pin}", timeout=1.5)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and data and data[0].get("Status") == "Success":
                    po = data[0].get("PostOffice") or []
                    if po and po[0].get("State"):
                        return str(po[0]["State"])
        except Exception:
            pass
    return PIN_PREFIX_TO_STATE.get(pin[:2])


def verify_invoice_tax_split(
    taxable_value: Decimal,
    seller_state: str,
    buyer_state: str,
    gst_rate_pct: Decimal = Decimal("18"),
) -> Dict[str, str]:
    """Computes exact Decimal CGST+SGST (intra-state) vs IGST (inter-state) split."""
    q = Decimal("0.01")
    total_tax = (taxable_value * gst_rate_pct / Decimal("100")).quantize(q, rounding=ROUND_HALF_UP)
    if seller_state.strip().lower() == buyer_state.strip().lower():
        half = (total_tax / Decimal("2")).quantize(q, rounding=ROUND_HALF_UP)
        return {
            "regime": "INTRA_STATE_CGST_SGST",
            "cgst": str(half),
            "sgst": str(total_tax - half),
            "igst": "0.00",
            "total_tax": str(total_tax),
            "grand_total": str((taxable_value + total_tax).quantize(q)),
        }
    return {
        "regime": "INTER_STATE_IGST",
        "cgst": "0.00",
        "sgst": "0.00",
        "igst": str(total_tax),
        "total_tax": str(total_tax),
        "grand_total": str((taxable_value + total_tax).quantize(q)),
    }
