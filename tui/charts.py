"""Chart rendering for terminal visualization."""
from typing import List, Optional
from rich.text import Text


# Unicode block characters for sparklines
SPARK_CHARS = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]


def render_sparkline(values: List[float], width: int = 40) -> str:
    """
    Render a sparkline from a list of values.

    Args:
        values: List of numeric values
        width: Maximum width of sparkline

    Returns:
        Sparkline string using Unicode block characters
    """
    if not values:
        return "No data"

    # Limit to width characters
    if len(values) > width:
        step = len(values) / width
        sampled = [values[int(i * step)] for i in range(width)]
    else:
        sampled = values

    # Normalize to 0-1 range
    min_val = min(sampled)
    max_val = max(sampled)
    range_val = max_val - min_val

    # Generate sparkline
    spark = []
    for val in sampled:
        if range_val == 0:
            # All values are the same, use middle character
            char_index = len(SPARK_CHARS) // 2
        else:
            normalized = (val - min_val) / range_val
            char_index = min(int(normalized * len(SPARK_CHARS)), len(SPARK_CHARS) - 1)
        spark.append(SPARK_CHARS[char_index])

    return "".join(spark)


def render_bar_chart(
    labels: List[str],
    values: List[int],
    max_width: int = 30,
    color: str = "green"
) -> str:
    """
    Render a horizontal bar chart.

    Args:
        labels: List of labels for each bar
        values: List of values for each bar
        max_width: Maximum bar width in characters
        color: Rich color name for bars

    Returns:
        Formatted bar chart string
    """
    if not labels or not values:
        return ""

    lines = []
    max_val = max(values) if values else 1

    for label, value in zip(labels, values):
        # Calculate bar length
        bar_len = int((value / max_val) * max_width) if max_val > 0 else 0
        bar = "█" * bar_len

        # Format line
        lines.append(f"{label:>5}  │{bar} {value:,}")

    return "\n".join(lines)


def render_status_distribution(
    status_2xx: int,
    status_3xx: int,
    status_4xx: int,
    status_5xx: int,
    max_width: int = 30
) -> str:
    """
    Render status code distribution as bar chart.

    Args:
        status_2xx: Count of 2xx responses
        status_3xx: Count of 3xx responses
        status_4xx: Count of 4xx responses
        status_5xx: Count of 5xx responses
        max_width: Maximum bar width

    Returns:
        Formatted distribution chart
    """
    total = status_2xx + status_3xx + status_4xx + status_5xx
    if total == 0:
        return "No data"

    lines = []

    # 2xx - Green
    bar_len = int((status_2xx / total) * max_width)
    lines.append(f"[green]2xx[/]: [green]{'█' * bar_len}[/] {status_2xx:,} ({status_2xx/total*100:.1f}%)")

    # 3xx - Cyan
    bar_len = int((status_3xx / total) * max_width)
    lines.append(f"[cyan]3xx[/]: [cyan]{'█' * bar_len}[/] {status_3xx:,} ({status_3xx/total*100:.1f}%)")

    # 4xx - Yellow
    bar_len = int((status_4xx / total) * max_width)
    lines.append(f"[yellow]4xx[/]: [yellow]{'█' * bar_len}[/] {status_4xx:,} ({status_4xx/total*100:.1f}%)")

    # 5xx - Red
    bar_len = int((status_5xx / total) * max_width)
    lines.append(f"[red]5xx[/]: [red]{'█' * bar_len}[/] {status_5xx:,} ({status_5xx/total*100:.1f}%)")

    return "\n".join(lines)


def render_hourly_traffic_chart(
    hourly_data: List[tuple[str, int]],
    max_width: int = 40
) -> str:
    """
    Render hourly traffic as horizontal bar chart.

    Args:
        hourly_data: List of (hour_label, count) tuples
        max_width: Maximum bar width

    Returns:
        Formatted hourly chart
    """
    if not hourly_data:
        return "No data"

    lines = []
    max_count = max(count for _, count in hourly_data) if hourly_data else 1

    for hour, count in hourly_data[-12:]:  # Last 12 hours
        time_label = hour.split()[-1] if ' ' in hour else hour
        bar_len = int((count / max_count) * max_width) if max_count > 0 else 0
        bar = "█" * bar_len
        lines.append(f"{time_label:>5}  │{bar} {count:,}")

    return "\n".join(lines)


def render_error_rate_sparkline(error_rates: List[float], width: int = 40) -> str:
    """
    Render error rate trend as sparkline.

    Args:
        error_rates: List of error rate percentages
        width: Width of sparkline

    Returns:
        Formatted sparkline with labels
    """
    if not error_rates:
        return "No data"

    spark = render_sparkline(error_rates, width)

    # Add min/max labels
    min_rate = min(error_rates)
    max_rate = max(error_rates)

    lines = [
        f"Error Rate Trend:",
        f"  {spark}",
        f"  Min: {min_rate:.1f}%  Max: {max_rate:.1f}%  Avg: {sum(error_rates)/len(error_rates):.1f}%"
    ]

    return "\n".join(lines)


def render_charts_dashboard(
    hourly_traffic: List[tuple[str, int]],
    error_rates: List[float],
    status_2xx: int,
    status_3xx: int,
    status_4xx: int,
    status_5xx: int,
) -> str:
    """
    Render complete charts dashboard.

    Args:
        hourly_traffic: List of (hour, count) tuples
        error_rates: List of error rates
        status_2xx: 2xx count
        status_3xx: 3xx count
        status_4xx: 4xx count
        status_5xx: 5xx count

    Returns:
        Complete dashboard string
    """
    lines = [
        "[bold]📊 TRAFFIC OVER TIME[/]",
        render_hourly_traffic_chart(hourly_traffic),
        "",
        "[bold]📈 ERROR RATE TREND[/]",
        render_error_rate_sparkline(error_rates),
        "",
        "[bold]📋 STATUS CODE DISTRIBUTION[/]",
        render_status_distribution(status_2xx, status_3xx, status_4xx, status_5xx),
    ]

    return "\n".join(lines)
