import base64
import io
import qrcode

def qr_png_base64(data: str) -> str:
    """Return a data URI (base64) for a PNG QR of the provided data string."""
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"