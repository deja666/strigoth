"""Log parser module for web server access logs.

This module provides parsers for various web server log formats including
Nginx and Apache (Combined and Common formats), with automatic format detection.
"""
from parser.apache import parse_line as parse_apache_line
from parser.detector import (
    LogFormat,
    detect_file_format,
    detect_format,
    get_parser_for_format,
    parse_with_auto_detect,
)
from parser.nginx import parse_line as parse_nginx_line

__all__ = [
    "parse_nginx_line",
    "parse_apache_line",
    "detect_format",
    "detect_file_format",
    "get_parser_for_format",
    "parse_with_auto_detect",
    "LogFormat",
]
