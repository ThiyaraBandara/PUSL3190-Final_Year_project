TRANSLATIONS = {
    'en': {
        'report_title': 'Phishing Detection Report',
        'generated_on': 'Generated on',
        # Add more keys as needed
    },
    'si': {
        'report_title': 'පිෂින්ග් අනාවරණ වාර්තාව',
        'generated_on': 'නිපදවූ දිනය',
        # Add more keys as needed
    },
    'ta': {
        'report_title': 'பிஷிங் கண்டறிதல் அறிக்கை',
        'generated_on': 'உருவாக்கப்பட்ட தேதி',
        # Add more keys as needed
    },
    'fr': {
        'report_title': 'Rapport de détection de phishing',
        'generated_on': 'Généré le',
        # Add more keys as needed
    },
    'es': {
        'report_title': 'Informe de detección de phishing',
        'generated_on': 'Generado el',
        # Add more keys as needed
    },
}

def translate(key, lang='en'):
    return TRANSLATIONS.get(lang, TRANSLATIONS['en']).get(key, key) 