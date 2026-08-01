"""Safe dependency-free charts, rendering, media, and coordinate conversion."""

from __future__ import annotations

import base64
import csv
import html
import math
import re
from collections.abc import Iterable

from ..registry import operation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, char_rep, require_int


def _rows(value: Data, args: Args) -> tuple[list[str], list[list[float]]]:
    record_delimiter = char_rep(arg(args, 0, "Line feed"), "\n")
    field_delimiter = char_rep(arg(args, 1, "Comma"), ",")
    records = to_text(value).split(record_delimiter)
    parsed = list(csv.reader(records, delimiter=field_delimiter))
    headers: list[str] = []
    if bool(arg(args, 2, True)) and parsed:
        headers = parsed.pop(0)
    numeric: list[list[float]] = []
    for row in parsed:
        try:
            numeric.append([float(field.strip()) for field in row if field.strip()])
        except ValueError:
            continue
    return headers, numeric


def _bounds(points: Iterable[tuple[float, float]]) -> tuple[float, float, float, float]:
    materialized = list(points)
    if not materialized:
        return 0, 1, 0, 1
    xs, ys = zip(*materialized, strict=True)
    minimum_x, maximum_x = min(xs), max(xs)
    minimum_y, maximum_y = min(ys), max(ys)
    if minimum_x == maximum_x:
        maximum_x += 1
    if minimum_y == maximum_y:
        maximum_y += 1
    return minimum_x, maximum_x, minimum_y, maximum_y


def _svg_start(title: str, x_label: str, y_label: str) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 500" '
        'role="img" style="background:white;color:#222">'
        f"<title>{html.escape(title)}</title>"
        '<path d="M60 20V450H780" fill="none" stroke="currentColor"/>'
        f'<text x="420" y="490" text-anchor="middle">{html.escape(x_label)}</text>'
        f'<text x="18" y="230" text-anchor="middle" transform="rotate(-90 18 230)">'
        f"{html.escape(y_label)}</text>"
    )


def _project(
    point: tuple[float, float], bounds: tuple[float, float, float, float]
) -> tuple[float, float]:
    minimum_x, maximum_x, minimum_y, maximum_y = bounds
    return (
        60 + (point[0] - minimum_x) / (maximum_x - minimum_x) * 720,
        450 - (point[1] - minimum_y) / (maximum_y - minimum_y) * 420,
    )


@operation("Scatter chart", category="Visualisation")
def scatter_chart(value: Data, args: Args) -> Data:
    headers, rows = _rows(value, args)
    points = [(row[0], row[1]) for row in rows if len(row) >= 2]
    bounds = _bounds(points)
    colour = html.escape(str(arg(args, 6, "mediumseagreen")), quote=True)
    radius = max(0.5, min(100.0, float(arg(args, 7, 10))))
    svg = _svg_start(
        "Scatter chart",
        str(arg(args, 3, headers[0] if headers else "X")),
        str(arg(args, 4, headers[1] if len(headers) > 1 else "Y")),
    )
    for index, point in enumerate(points):
        x, y = _project(point, bounds)
        point_colour = colour
        if bool(arg(args, 8, False)) and len(rows[index]) >= 3:
            shade = max(0, min(255, round(rows[index][2])))
            point_colour = f"rgb({shade},80,{255 - shade})"
        svg += (
            f'<circle cx="{x:.2f}" cy="{y:.2f}" r="{radius:.2f}" '
            f'fill="{point_colour}" fill-opacity=".75"/>'
        )
    return svg + "</svg>"


@operation("Series chart", category="Visualisation")
def series_chart(value: Data, args: Args) -> Data:
    headers, rows = _rows(value, args)
    if not rows:
        return _svg_start("Series chart", "X", "Y") + "</svg>"
    series_count = max(len(row) for row in rows) - 1
    all_points = [(row[0], item) for row in rows for item in row[1:]]
    bounds = _bounds(all_points)
    colours = [
        item.strip()
        for item in str(arg(args, 4, "mediumseagreen, dodgerblue, tomato")).split(",")
        if item.strip()
    ]
    svg = _svg_start("Series chart", str(arg(args, 2, headers[0] if headers else "X")), "Value")
    for series in range(series_count):
        points = [(row[0], row[series + 1]) for row in rows if len(row) > series + 1]
        projected = [_project(point, bounds) for point in points]
        colour = html.escape(colours[series % len(colours)] if colours else "black", quote=True)
        path = " ".join(
            ("M" if index == 0 else "L") + f"{x:.2f},{y:.2f}"
            for index, (x, y) in enumerate(projected)
        )
        svg += f'<path d="{path}" fill="none" stroke="{colour}" stroke-width="2"/>'
    return svg + "</svg>"


def _colour(value: float, maximum: float) -> str:
    ratio = 0 if maximum <= 0 else max(0.0, min(1.0, value / maximum))
    return f"rgb({round(255 * ratio)},{round(90 + 100 * (1 - ratio))},{round(255 * (1 - ratio))})"


@operation("Heatmap chart", category="Visualisation")
def heatmap_chart(value: Data, args: Args) -> Data:
    _, rows = _rows(value, args)
    points = [(row[0], row[1]) for row in rows if len(row) >= 2]
    vertical = max(1, min(200, require_int(arg(args, 2, 25), name="vertical bins")))
    horizontal = max(1, min(200, require_int(arg(args, 3, 25), name="horizontal bins")))
    bounds = _bounds(points)
    bins = [[0] * horizontal for _ in range(vertical)]
    for point in points:
        x, y = _project(point, bounds)
        column = min(horizontal - 1, max(0, int((x - 60) / 720 * horizontal)))
        row = min(vertical - 1, max(0, int((450 - y) / 420 * vertical)))
        bins[row][column] += 1
    maximum = max((amount for row in bins for amount in row), default=1)
    svg = _svg_start("Heatmap", str(arg(args, 5, "X")), str(arg(args, 6, "Y")))
    for row in range(vertical):
        for column in range(horizontal):
            svg += (
                f'<rect x="{60 + column * 720 / horizontal:.2f}" '
                f'y="{30 + row * 420 / vertical:.2f}" width="{720 / horizontal:.2f}" '
                f'height="{420 / vertical:.2f}" fill="{_colour(bins[row][column], maximum)}"/>'
            )
    return svg + "</svg>"


@operation("Hex Density chart", category="Visualisation")
def hex_density_chart(value: Data, args: Args) -> Data:
    _, rows = _rows(value, args)
    points = [(row[0], row[1]) for row in rows if len(row) >= 2]
    bounds = _bounds(points)
    radius = max(2.0, min(100.0, float(arg(args, 3, 15))))
    buckets: dict[tuple[int, int], int] = {}
    for point in points:
        x, y = _project(point, bounds)
        bucket = round(x / (radius * 1.5)), round(y / (radius * math.sqrt(3)))
        buckets[bucket] = buckets.get(bucket, 0) + 1
    maximum = max(buckets.values(), default=1)
    svg = _svg_start("Hex density", str(arg(args, 5, "X")), str(arg(args, 6, "Y")))
    for (column, row), amount in buckets.items():
        center_x = column * radius * 1.5
        center_y = row * radius * math.sqrt(3)
        points_text = " ".join(
            f"{center_x + radius * math.cos(math.radians(60 * index)):.2f},"
            f"{center_y + radius * math.sin(math.radians(60 * index)):.2f}"
            for index in range(6)
        )
        svg += f'<polygon points="{points_text}" fill="{_colour(amount, maximum)}"/>'
    return svg + "</svg>"


def _inline_markdown(text: str, new_tab: bool) -> str:
    escaped = html.escape(text)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    escaped = re.sub(r"(?<!\*)\*([^*]+)\*", r"<em>\1</em>", escaped)
    target = ' target="_blank" rel="noopener noreferrer"' if new_tab else ""
    return re.sub(
        r"\[([^\]]+)]\((https?://[^\s)]+)\)",
        lambda match: (
            f'<a href="{html.escape(match.group(2), quote=True)}"{target}>{match.group(1)}</a>'
        ),
        escaped,
    )


@operation("Render Markdown", category="Rendering")
def render_markdown(value: Data, args: Args) -> Data:
    auto_links = bool(arg(args, 0, False))
    new_tab = bool(arg(args, 2, False))
    output: list[str] = []
    in_code = False
    code: list[str] = []
    for line in to_text(value).splitlines():
        if line.startswith("```"):
            if in_code:
                output.append("<pre><code>" + html.escape("\n".join(code)) + "</code></pre>")
                code = []
            in_code = not in_code
            continue
        if in_code:
            code.append(line)
            continue
        heading = re.match(r"^(#{1,6})\s+(.*)$", line)
        if heading:
            level = len(heading.group(1))
            output.append(f"<h{level}>{_inline_markdown(heading.group(2), new_tab)}</h{level}>")
        elif line.startswith("- "):
            output.append(f"<ul><li>{_inline_markdown(line[2:], new_tab)}</li></ul>")
        elif line:
            rendered = _inline_markdown(line, new_tab)
            if auto_links:
                target = ' target="_blank" rel="noopener noreferrer"' if new_tab else ""
                rendered = re.sub(
                    r"(?<![\"=])(https?://[^\s<]+)", rf'<a href="\1"{target}>\1</a>', rendered
                )
            output.append(f"<p>{rendered}</p>")
    if in_code:
        output.append("<pre><code>" + html.escape("\n".join(code)) + "</code></pre>")
    return "\n".join(output)


@operation("Render PDF", category="Rendering")
def render_pdf(value: Data, args: Args) -> Data:
    data = (
        base64.b64decode(to_text(value), validate=True)
        if str(arg(args, 0, "Base64")) == "Base64"
        else to_bytes(value)
    )
    if data and not data.startswith(b"%PDF-"):
        raise ValueError("Input does not appear to be a PDF file")
    return data


_MEDIA_SIGNATURES = (
    b"ID3",
    b"OggS",
    b"RIFF",
    b"\x1aE\xdf\xa3",
    b"\xff\xfb",
    b"\xff\xf3",
    b"\xff\xf2",
)


@operation("Play Media", category="Rendering")
def play_media(value: Data, args: Args) -> Data:
    input_format = str(arg(args, 0, "Raw"))
    if input_format == "Hex":
        data = bytes.fromhex(to_text(value))
    elif input_format == "Base64":
        data = base64.b64decode(to_text(value), validate=True)
    else:
        data = to_bytes(value)
    if data and not (
        data.startswith(_MEDIA_SIGNATURES) or (len(data) > 12 and data[4:8] == b"ftyp")
    ):
        raise ValueError("Invalid or unrecognised audio/video file type")
    return data


@operation("Syntax highlighter", category="Rendering")
def syntax_highlighter(value: Data, args: Args) -> Data:
    language = html.escape(str(arg(args, 0, "Auto")), quote=True)
    escaped = html.escape(to_text(value))
    pattern = re.compile(
        r"(&quot;.*?&quot;|&#x27;.*?&#x27;|\b\d+(?:\.\d+)?\b|\b(?:def|class|return|if|else|for|while|import|from|const|let|function)\b)"
    )
    highlighted = pattern.sub(lambda match: f'<span class="token">{match.group(0)}</span>', escaped)
    return f'<pre class="syntax" data-language="{language}"><code>{highlighted}</code></pre>'


_GEOHASH_ALPHABET = "0123456789bcdefghjkmnpqrstuvwxyz"


def _geohash_decode(value: str) -> tuple[float, float]:
    latitude = [-90.0, 90.0]
    longitude = [-180.0, 180.0]
    use_longitude = True
    for character in value.lower().strip():
        try:
            number = _GEOHASH_ALPHABET.index(character)
        except ValueError as exc:
            raise ValueError("Invalid geohash") from exc
        for bit in (16, 8, 4, 2, 1):
            interval = longitude if use_longitude else latitude
            midpoint = sum(interval) / 2
            interval[0 if number & bit else 1] = midpoint
            use_longitude = not use_longitude
    return sum(latitude) / 2, sum(longitude) / 2


def _geohash_encode(latitude: float, longitude: float, precision: int) -> str:
    intervals = [[-90.0, 90.0], [-180.0, 180.0]]
    output: list[str] = []
    number = bit_count = 0
    use_longitude = True
    while len(output) < precision:
        coordinate = longitude if use_longitude else latitude
        interval = intervals[1 if use_longitude else 0]
        midpoint = sum(interval) / 2
        number = (number << 1) | int(coordinate >= midpoint)
        interval[0 if coordinate >= midpoint else 1] = midpoint
        bit_count += 1
        use_longitude = not use_longitude
        if bit_count == 5:
            output.append(_GEOHASH_ALPHABET[number])
            number = bit_count = 0
    return "".join(output)


def _coordinates(text: str, input_format: str) -> tuple[float, float]:
    if input_format == "Geohash" or (
        input_format == "Auto" and re.fullmatch(r"[0-9bc-hjkmnp-z]+", text.strip(), re.I)
    ):
        return _geohash_decode(text)
    directions = re.findall(r"[NSEW]", text.upper())
    numbers = [float(value) for value in re.findall(r"[-+]?\d+(?:\.\d+)?", text)]
    if input_format == "Degrees Minutes Seconds" or len(numbers) >= 6:
        if len(numbers) < 6:
            raise ValueError("DMS input requires latitude and longitude degrees, minutes, seconds")
        latitude = numbers[0] + numbers[1] / 60 + numbers[2] / 3600
        longitude = numbers[3] + numbers[4] / 60 + numbers[5] / 3600
    elif input_format == "Degrees Decimal Minutes" or len(numbers) == 4:
        latitude = numbers[0] + numbers[1] / 60
        longitude = numbers[2] + numbers[3] / 60
    elif len(numbers) >= 2:
        latitude, longitude = numbers[:2]
    else:
        raise ValueError("Could not parse a coordinate pair")
    if "S" in directions:
        latitude = -abs(latitude)
    if "W" in directions:
        longitude = -abs(longitude)
    if not -90 <= latitude <= 90 or not -180 <= longitude <= 180:
        raise ValueError("Latitude or longitude is outside its valid range")
    return latitude, longitude


def _coordinate_output(
    latitude: float,
    longitude: float,
    output_format: str,
    delimiter: str,
    direction: str,
    precision: int,
) -> str:
    if output_format == "Geohash":
        return _geohash_encode(latitude, longitude, max(1, min(12, precision)))
    if output_format in {
        "Military Grid Reference System",
        "Ordnance Survey National Grid",
        "Universal Transverse Mercator",
    }:
        raise ValueError(f"Dependency-free conversion to {output_format} is not available")
    values: list[str] = []
    for coordinate, positive, negative in ((latitude, "N", "S"), (longitude, "E", "W")):
        compass = positive if coordinate >= 0 else negative
        absolute = abs(coordinate)
        if output_format == "Degrees Minutes Seconds":
            degrees = int(absolute)
            minutes_full = (absolute - degrees) * 60
            minutes = int(minutes_full)
            item = f"{degrees}° {minutes}' {(minutes_full - minutes) * 60:.{precision}f}\""
        elif output_format == "Degrees Decimal Minutes":
            degrees = int(absolute)
            item = f"{degrees}° {(absolute - degrees) * 60:.{precision}f}'"
        else:
            item = f"{absolute:.{precision}f}"
        if direction == "Before":
            item = compass + " " + item
        elif direction == "After":
            item += " " + compass
        elif coordinate < 0:
            item = "-" + item
        values.append(item)
    return delimiter.join(values)


@operation("Convert co-ordinate format", category="Geography")
def convert_coordinate_format(value: Data, args: Args) -> Data:
    text = to_text(value)
    if not text.strip():
        return text
    input_format = str(arg(args, 0, "Auto"))
    output_format = str(arg(args, 2, "Decimal Degrees"))
    delimiter = char_rep(arg(args, 3, "Space"))
    direction = str(arg(args, 4, "None"))
    precision = max(0, require_int(arg(args, 5, 3), name="precision"))
    latitude, longitude = _coordinates(text, input_format)
    return _coordinate_output(latitude, longitude, output_format, delimiter, direction, precision)


@operation("Show on map", category="Geography")
def show_on_map(value: Data, args: Args) -> Data:
    zoom = max(0, min(22, require_int(arg(args, 0, 13), name="zoom")))
    input_format = str(arg(args, 1, "Auto"))
    latitude, longitude = _coordinates(to_text(value), input_format)
    x = 400 + longitude / 180 * 360
    y = 230 - latitude / 90 * 200
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 460" role="img">'
        f"<title>Map position {latitude:.6f}, {longitude:.6f}; zoom {zoom}</title>"
        '<rect width="800" height="460" fill="#e8eef3"/>'
        '<path d="M40 230H760M400 30V430" stroke="#9aa9b5" stroke-dasharray="5 5"/>'
        f'<circle cx="{x:.2f}" cy="{y:.2f}" r="10" fill="#d33"/>'
        f'<text x="{x + 14:.2f}" y="{y - 14:.2f}">{latitude:.6f}, {longitude:.6f}</text>'
        "</svg>"
    )
