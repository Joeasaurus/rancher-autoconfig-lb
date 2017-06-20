import LeeCaller

domains = [
    {
        'tld': 'shadowacre.ltd',
        'common_name': 'jme-test.shadowacre.ltd',
        'alt_names': ['whoknows.jme-test.shadowacre.ltd']
    },
    {
        'tld': 'shadowacre.ltd',
        'common_name': 'jme-test-2.shadowacre.ltd',
        'alt_names': ['whoknows.jme-test-2.shadowacre.ltd']
    }
]

LeeCaller.load()
print LeeCaller.request_certificates(domains)
