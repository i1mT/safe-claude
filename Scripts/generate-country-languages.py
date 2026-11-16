#!/usr/bin/env python3
"""Derive country language candidates from Unicode CLDR territory data."""
import json
import re
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = root / 'DataSources/CLDR/territoryInfo-48.json'
data = json.loads(source.read_text(encoding='utf-8'))['supplemental']
assert data['version']['_cldrVersion'] == '48'
lines = ['// Generated from Unicode CLDR 48 territoryInfo; see DataSources/CLDR/LICENSE.',
         '// Candidates include official languages and languages with >=5% reported speakers.',
         'import Foundation', '', 'public enum CountryLanguageCatalog {',
         '    public static let version = "CLDR-48-official-or-5-percent"',
         '    private static let countries: [String: [String]] = [']
for country, info in sorted(data['territoryInfo'].items()):
    if not re.fullmatch('[A-Z]{2}', country):
        continue
    languages = set()
    for language, attributes in info.get('languagePopulation', {}).items():
        status = attributes.get('_officialStatus', '')
        percentage = float(attributes.get('_populationPercent', '0'))
        if status in {'official', 'de_facto_official', 'official_regional'} or percentage >= 5:
            code = language.split('_')[0].lower()
            if re.fullmatch('[a-z]{2,3}', code) and code != 'und':
                languages.add(code)
    if languages:
        values = ', '.join('"' + item + '"' for item in sorted(languages))
        lines.append(f'        "{country}": [{values}],')
lines.extend(['    ]', '', '    public static func languages(for country: String) -> CountryLanguages? {',
              '        let code = country.uppercased()',
              '        guard let values = countries[code] else { return nil }',
              '        return CountryLanguages(countryCode: code, languages: values)',
              '    }', '}'])
(root / 'Sources/GuardCore/CountryLanguageCatalog.swift').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print('Generated country language catalog from CLDR 48')
