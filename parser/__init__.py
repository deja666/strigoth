# Parser module

from parser.nginx import parse_line as parse_nginx_line
from parser.apache import parse_line as parse_apache_line
from parser.detector import (
    detect_format,
    detect_file_format,
    get_parser_for_format,
    parse_with_auto_detect,
    LogFormat,
)

__all__ = [
    "parse_nginx_line",
    "parse_apache_line",
    "detect_format",
    "detect_file_format",
    "get_parser_for_format",
    "parse_with_auto_detect",
    "LogFormat",
]
