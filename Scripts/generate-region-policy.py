#!/usr/bin/env python3
"""Generate the reviewed region policy implementation from its pinned snapshot."""
import json
from datetime import datetime
from pathlib import Path

root = Path(__file__).resolve().parents[1]
data = json.loads((root / 'DataSources/region-policy-2026-11-12.json').read_text())
supported = sorted(data['supportedCountryCodes'])
unsupported = sorted(data['knownUnsupportedCountryCodes'])
assert len(set(supported)) == len(supported) and not set(supported).intersection(unsupported)
assert all(len(code) == 2 and code.isascii() and code.isupper() for code in supported + unsupported)
timestamp = lambda value: int(datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp())
lines = ['import Foundation', '', '/// Generated from DataSources/region-policy-2026-11-12.json.',
         '/// Ukraine and unlisted dependent territories remain unknown pending subdivision/sovereignty data.',
         'public enum RegionPolicy {', '    public enum Result: Equatable, Sendable { case supported, unsupported, unknown }',
         '    // Wait until the official calendar date has begun in all time zones.',
         f'    private static let starts = Date(timeIntervalSince1970: {timestamp(data["effectiveNotBefore"])})',
         f'    private static let expires = Date(timeIntervalSince1970: {timestamp(data["reviewExpiresAt"])})',
         '    private static let supported: Set<String> = [']
for offset in range(0, len(supported), 12):
    lines.append('        ' + ', '.join('"' + code + '"' for code in supported[offset:offset + 12]) + ',')
lines += ['    ]', '    private static let unsupported: Set<String> = [' + ', '.join('"' + code + '"' for code in unsupported) + ']',
          '', '    public static func classify(countryCode: String, at: Date = Date()) -> Result {',
          '        guard at >= starts && at < expires else { return .unknown }',
          '        let code = countryCode.uppercased()', '        if supported.contains(code) { return .supported }',
          '        if unsupported.contains(code) { return .unsupported }', '        return .unknown', '    }', '}']
(root / 'Sources/GuardCore/RegionPolicy.swift').write_text('\n'.join(lines) + '\n')
