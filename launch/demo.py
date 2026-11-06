"""Generate a reversible local redaction demo and its animated GIF.

All values are fictional/documentation-only fixtures. The demo never makes a
network request and only writes launch/demo.gif.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from veilrelay.detectors import BuiltinDetector, SecretDetector  # noqa: E402
from veilrelay.policy import PolicyConfig, PrivacyEngine  # noqa: E402
from veilrelay.vault import TokenVault  # noqa: E402


def main() -> None:
    from PIL import Image, ImageDraw, ImageFont

    original = (
        "Please send the project update to alice@example.test. "
        "The test Aadhaar-shaped value is 234567890127. "
        "The fake AWS key is AKIAIOSFODNN7EXAMPLE."
    )
    engine = PrivacyEngine([BuiltinDetector(), SecretDetector()], PolicyConfig())
    vault = TokenVault()
    safe = engine.scan(original, vault).safe_text
    upstream_reply = f"I will send the update to {vault.issue('EMAIL', 'alice@example.test')} " \
        f"and note the account {vault.issue('AADHAAR', '234567890127')}."
    restored = vault.restore(upstream_reply)

    font_path = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
    bold_path = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
    try:
        body = ImageFont.truetype(font_path, 18)
        title = ImageFont.truetype(bold_path, 24)
        small = ImageFont.truetype(font_path, 13)
    except OSError:
        body = title = small = ImageFont.load_default()

    frames = []
    panels = [
        ("01 / BEFORE: LOCAL PROMPT", original, "Sensitive text exists only in this local process."),
        ("02 / OUTBOUND: REDACTED", safe, "Only placeholders are sent to the configured upstream."),
        ("03 / MODEL RESPONSE", upstream_reply, "The model can reason over typed placeholders."),
        ("04 / CLIENT RESPONSE", restored, "Known placeholders are restored locally."),
    ]
    width, height = 1120, 430
    for heading, content, footer in panels:
        image = Image.new("RGB", (width, height), (12, 18, 28))
        draw = ImageDraw.Draw(image)
        draw.rectangle((0, 0, width, 64), fill=(19, 32, 48))
        draw.text((38, 18), "VEILRELAY   /   LOCAL PRIVACY PROXY", font=small, fill=(137, 183, 213))
        draw.text((38, 100), heading, font=title, fill=(236, 242, 248))
        draw.line((38, 147, width - 38, 147), fill=(53, 80, 101), width=2)
        wrapped: list[str] = []
        line = ""
        for word in content.replace("\n", " ").split():
            candidate = f"{line} {word}".strip()
            if draw.textbbox((0, 0), candidate, font=body)[2] > width - 100:
                wrapped.append(line)
                line = word
            else:
                line = candidate
        if line:
            wrapped.append(line)
        y = 190
        for row in wrapped:
            draw.text((42, y), row, font=body, fill=(123, 219, 180) if "<" in row else (213, 223, 233))
            y += 38
        draw.line((38, height - 76, width - 38, height - 76), fill=(53, 80, 101), width=1)
        draw.text((38, height - 54), footer, font=small, fill=(155, 174, 191))
        draw.text((width - 385, height - 54), "SIMULATED / NO UPSTREAM REQUEST", font=small, fill=(236, 174, 115))
        frames.append(image)

    output = ROOT / "launch" / "demo.gif"
    frames[0].save(
        output,
        save_all=True,
        append_images=frames[1:],
        duration=[1500, 1800, 1500, 1800],
        loop=0,
        optimize=True,
    )
    print(f"Wrote {output.relative_to(ROOT)}")
    vault.clear()


if __name__ == "__main__":
    main()
