from io import BytesIO
from reportlab.pdfgen import canvas
from pypdf import PdfReader, PdfWriter
from PIL import Image, ImageDraw, ImageFont

def watermark_pdf(data: bytes, label: str) -> bytes:
    source = PdfReader(BytesIO(data))
    writer = PdfWriter()
    for page in source.pages:
        overlay_bytes = BytesIO()
        width = float(page.mediabox.width); height = float(page.mediabox.height)
        c = canvas.Canvas(overlay_bytes, pagesize=(width, height))
        c.saveState(); c.setFillColorRGB(0.72, 0.1, 0.16, alpha=0.20)
        c.setFont("Helvetica-Bold", max(14, min(width, height) / 25))
        c.translate(width / 2, height / 2); c.rotate(35)
        c.drawCentredString(0, 0, label[:100]); c.restoreState(); c.save()
        overlay_bytes.seek(0)
        page.merge_page(PdfReader(overlay_bytes).pages[0])
        writer.add_page(page)
    output = BytesIO(); writer.write(output); return output.getvalue()

def watermark_image(data: bytes, label: str) -> bytes:
    image = Image.open(BytesIO(data)).convert("RGBA")
    layer = Image.new("RGBA", image.size, (255, 255, 255, 0))
    draw = ImageDraw.Draw(layer)
    try: font = ImageFont.truetype("arial.ttf", max(12, image.width // 35))
    except OSError: font = ImageFont.load_default()
    text = label[:100]
    box = draw.textbbox((0, 0), text, font=font)
    x = max(5, image.width - (box[2] - box[0]) - 15); y = max(5, image.height - (box[3] - box[1]) - 15)
    draw.rectangle((x-5, y-5, min(image.width, x+box[2]+5), min(image.height, y+box[3]+5)), fill=(255,255,255,140))
    draw.text((x, y), text, fill=(160, 25, 40, 230), font=font)
    combined = Image.alpha_composite(image, layer).convert("RGB")
    out = BytesIO(); combined.save(out, format="PNG"); return out.getvalue()
