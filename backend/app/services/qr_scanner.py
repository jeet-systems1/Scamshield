"""
QR Code scanner service.
Extracts URL from QR image, then passes to URL scanner.
"""
import io
from typing import Optional
from PIL import Image


def extract_url_from_qr(image_bytes: bytes) -> Optional[str]:
    """
    Decode a QR code image and return the embedded URL/text.
    Returns None if no QR code found or decode fails.
    """
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode

        image = Image.open(io.BytesIO(image_bytes))
        decoded_objects = pyzbar_decode(image)

        if not decoded_objects:
            return None

        # Take the first QR code found
        raw_data = decoded_objects[0].data.decode("utf-8", errors="replace").strip()
        return raw_data if raw_data else None

    except ImportError:
        # pyzbar requires system library (zbar) — graceful fallback
        return None
    except Exception:
        return None
