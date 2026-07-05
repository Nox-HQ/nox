# Clean sample: an embedded base64 PNG icon. A naive high-entropy
# secret detector might mistake this long base64 blob for a credential,
# but it is public image data. Any finding on this file is a FALSE
# POSITIVE. No nox-expect annotations here on purpose.

TRANSPARENT_PIXEL_PNG = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4"
    "2mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)


def icon_bytes():
    import base64

    return base64.b64decode(TRANSPARENT_PIXEL_PNG)
