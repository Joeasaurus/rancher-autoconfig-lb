import LeeCaller

domains = [
    {
        'tld': 'shadowacre.ltd',
        'common_name': 'jme-test.shadowacre.ltd',
        'alt_names': ['whoknows.jme-test.shadowacre.ltd']
    }
]

LeeCaller.load()
LeeCaller.request_certificates(domains)
