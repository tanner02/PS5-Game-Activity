#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Cache public PlayStation artwork for one title or all console metadata entries."""
import argparse
import ftplib
import hashlib
import hmac
import io
import json
import posixpath
import re
import sys
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser

META_LIMIT, PAGE_LIMIT, MANIFEST_LIMIT = 1024 * 1024, 2 * 1024 * 1024, 256 * 1024
TITLE = re.compile(r'(?:PPSA|CUSA)[0-9]{5}\Z')
CONTENT = re.compile(r'[A-Z]{2}[0-9]{4}-((?:PPSA|CUSA)[0-9]{5})_[0-9]{2}-[A-Za-z0-9_]{16}\Z')
DIGITS = re.compile(r'[0-9]{1,12}\Z')
LOCALES = {'EP': 'en-gb', 'HP': 'en-hk', 'JP': 'ja-jp', 'UP': 'en-us'}
TMDB_PREFIX = 'https://tmdb.np.dl.playstation.net/tmdb2/'
PS4_IMAGE_PREFIX = 'https://gs2-sec.ww.prod.dl.playstation.net/gs2-sec/appkgo/prod/'
# Sony's public TMDB title-hashing convention, also used by the payload.
TMDB_KEY = bytes.fromhex(
    'F5DE66D2680E255B2DF79E74F890EBF349262F618BCAE2A9ACCDEE5156CE8DF2'
    'CDF2D48C71173CDC2594465B87405D197CF1AED3B7E9671EEB56CA6753C2E6B0'
)


def image_url(value):
    return (isinstance(value, str) and len(value) <= 256 and
            value.startswith(('https://image.api.playstation.com/', 'https://image.dl.playstation.net/', PS4_IMAGE_PREFIX)) and
            re.fullmatch(r'[A-Za-z0-9:/._?=&%+~\-]+', value) is not None)


def store_url(content='', concept=''):
    if DIGITS.fullmatch(concept):
        return 'https://store.playstation.com/en-us/concept/' + concept
    locale = LOCALES.get(content[:2])
    if CONTENT.fullmatch(content) and locale:
        return 'https://store.playstation.com/' + locale + '/product/' + content
    raise ValueError('No supported public Store identifier in game metadata')


def valid_store_url(value):
    if not isinstance(value, str):
        return False
    if re.fullmatch(r'https://store\.playstation\.com/en-us/concept/[0-9]{1,12}', value):
        return True
    match = re.fullmatch(r'https://store\.playstation\.com/([^/]+)/product/([^/]+)', value)
    return bool(match and CONTENT.fullmatch(match[2]) and LOCALES.get(match[2][:2]) == match[1])


def parse_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON field')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def retrieve(ftp, path, limit):
    data = bytearray()
    def receive(block):
        if len(data) + len(block) > limit:
            raise ValueError('FTP file exceeds size limit')
        data.extend(block)
    try:
        ftp.retrbinary('RETR ' + path, receive)
    except ftplib.error_perm as error:
        if str(error).startswith('550'):
            return None
        raise
    return bytes(data)


class StoreRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != 'https' or parsed.hostname != 'store.playstation.com' or parsed.port not in (None, 443) or parsed.username or parsed.password:
            raise ValueError('Store redirected outside its public HTTPS origin')
        return super().redirect_request(request, fp, code, message, headers, newurl)


class StorePage(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.current, self.parts, self.documents = None, [], []

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == 'script' and (attrs.get('type') == 'application/ld+json' or attrs.get('id') == '__NEXT_DATA__'):
            self.current, self.parts = attrs.get('id') == '__NEXT_DATA__', []

    def handle_data(self, data):
        if self.current is not None:
            self.parts.append(data)

    def handle_endtag(self, tag):
        if tag == 'script' and self.current is not None:
            try:
                self.documents.append((self.current, parse_json(''.join(self.parts))))
            except (ValueError, RecursionError):
                pass
            self.current, self.parts = None, []


def artwork(page, content, concept):
    parser = StorePage()
    parser.feed(page)
    concept_matches, products = False, []
    for is_next, value in parser.documents:
        if is_next and isinstance(value, dict):
            props = value.get('props', {})
            page_props = props.get('pageProps', {}) if isinstance(props, dict) else {}
            concept_matches = bool(isinstance(page_props, dict) and concept and page_props.get('conceptId') == concept)
        elif not is_next:
            products.extend(value if isinstance(value, list) else [value])
    for product in products:
        if (isinstance(product, dict) and product.get('@type') == 'Product' and
                (concept_matches or (content and product.get('sku') == content)) and image_url(product.get('image'))):
            return product['image']
    raise ValueError('No matching Product with an allowed public artwork URL')


def manifest(data):
    value = {'version': 1, 'images': {}} if data is None else parse_json(data)
    if (not isinstance(value, dict) or set(value) != {'version', 'images'} or type(value['version']) is not int or value['version'] != 1 or
            not isinstance(value['images'], dict) or len(value['images']) > 32 or
            any(not (TITLE.fullmatch(key) or valid_store_url(key)) or not image_url(image) for key, image in value['images'].items())):
        raise ValueError('Existing artwork manifest is invalid; refusing to replace it')
    return value


def install(ftp, directory, images):
    target = directory + '/game-artwork.json'
    old = retrieve(ftp, target, MANIFEST_LIMIT)
    value = manifest(old)
    value['images'].update(images)
    if len(value['images']) > 32:
        raise ValueError('Artwork manifest would exceed 32 entries')
    data = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
    if len(data) > MANIFEST_LIMIT:
        raise ValueError('Artwork manifest exceeds size limit')
    parts = directory.split('/')
    for index in range(1, len(parts)):
        path = '/'.join(parts[:index + 1])
        try:
            ftp.mkd(path)
        except ftplib.error_perm as error:
            if not str(error).startswith('550'):
                raise
            ftp.cwd(path)  # Distinguish an existing directory from denied creation.
    unique = uuid.uuid4().hex
    temporary, backup = directory + '/.game-artwork-' + unique + '.tmp', target + '.' + unique + '.bak'
    staged, backed_up = False, False
    try:
        staged = True
        ftp.storbinary('STOR ' + temporary, io.BytesIO(data))
        if retrieve(ftp, temporary, MANIFEST_LIMIT) != data:
            raise ValueError('Staged artwork manifest verification failed')
        if retrieve(ftp, target, MANIFEST_LIMIT) != old:
            raise ValueError('Artwork manifest changed during update; refusing to overwrite it')
        if old is not None:
            ftp.rename(target, backup)
            backed_up = True
        try:
            ftp.rename(temporary, target)
            staged = False
        except Exception:
            if backed_up:
                ftp.rename(backup, target)
            raise
    finally:
        if staged:
            try:
                ftp.delete(temporary)  # Never delete anything except our unique temp.
            except ftplib.error_reply as error:
                if not str(error).startswith('226'):  # This server uses 226 for successful DELE.
                    raise
            except ftplib.all_errors:
                pass


def download(url, limit, *, accept):
    request = urllib.request.Request(url, headers={
        'User-Agent': 'PBS-Discord-Artwork/1', 'Accept': accept, 'Accept-Encoding': 'identity',
    })
    with urllib.request.build_opener(StoreRedirect()).open(request, timeout=8) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Public artwork metadata exceeds size limit')
    return data


def ps4_artwork(title):
    np_title = title + '_00'
    digest = hmac.digest(TMDB_KEY, np_title.encode('ascii'), 'sha1').hex().upper()
    url = f'{TMDB_PREFIX}{np_title}_{digest}/{np_title}.json'
    data = parse_json(download(url, META_LIMIT, accept='application/json'))
    if not isinstance(data, dict) or data.get('npTitleId') != np_title:
        raise ValueError('PlayStation metadata did not match the PS4 title ID')
    icons = data.get('icons')
    for entry in icons if isinstance(icons, list) else []:
        value = entry.get('icon') if isinstance(entry, dict) else None
        if isinstance(value, str):
            if value.startswith('http://'):
                value = 'https://' + value[7:]
            if value.startswith(PS4_IMAGE_PREFIX + np_title + '/') and image_url(value):
                return value
    raise ValueError('No public PlayStation icon for this PS4 title')


def ps5_metadata(ftp, title):
    raw = retrieve(ftp, f'/user/appmeta/{title}/param.json', META_LIMIT)
    metadata = parse_json(raw) if raw is not None else None
    if not isinstance(metadata, dict) or metadata.get('titleId') != title:
        raise ValueError('Matching param.json is missing or invalid')
    content, concept = metadata.get('contentId', ''), metadata.get('conceptId', '')
    match = CONTENT.fullmatch(content) if isinstance(content, str) else None
    if not match or match[1] != title:
        content = ''
    if not isinstance(concept, str) or not DIGITS.fullmatch(concept):
        concept = ''
    return content, concept


def resolve_title(title, identifiers):
    if title.startswith('CUSA'):
        return ps4_artwork(title)
    content, concept = identifiers
    try:
        url = store_url(content, concept)
        page = download(url, PAGE_LIMIT, accept='text/html')
        return artwork(page.decode('utf-8'), content, concept)
    except (ValueError, OSError):
        if not concept or not content or content[:2] not in LOCALES:
            raise
    url = store_url(content)
    page = download(url, PAGE_LIMIT, accept='text/html')
    return artwork(page.decode('utf-8'), content, concept)


def installed_title_ids(ftp):
    ftp.cwd('/user/appmeta')
    entries = []
    ftp.retrlines('LIST', entries.append)
    names = {entry.rsplit(maxsplit=1)[-1] for entry in entries if entry.startswith('d')}
    return sorted(name for name in names if TITLE.fullmatch(name))


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument('--host', required=True)
    args.add_argument('--port', type=int, default=2121)
    selection = args.add_mutually_exclusive_group(required=True)
    selection.add_argument('--title')
    selection.add_argument('--all', action='store_true', help='Cache artwork for all title IDs in /user/appmeta')
    args.add_argument('--output-dir', default='/data/pbs-discord')
    options = args.parse_args()
    directory = options.output_dir.rstrip('/')
    if (options.title and not TITLE.fullmatch(options.title)) or not 1 <= options.port <= 65535:
        raise ValueError('Expected PPSA/CUSA plus five digits and a valid FTP port')
    if not directory.startswith('/') or directory != posixpath.normpath(directory) or any(ord(c) < 32 or c == chr(92) for c in directory):
        raise ValueError('Output directory must be an absolute normalized FTP path')
    with ftplib.FTP(timeout=10) as ftp:
        ftp.connect(options.host, options.port)
        ftp.login()
        titles = installed_title_ids(ftp) if options.all else [options.title]
        if not titles:
            raise ValueError('No PS4 or PS5 title IDs found')
        images = {}
        with ThreadPoolExecutor(max_workers=6) as workers:
            pending = {}
            for title in titles:
                try:
                    identifiers = ps5_metadata(ftp, title) if title.startswith('PPSA') else None
                    pending[title] = workers.submit(resolve_title, title, identifiers)
                except (ValueError, OSError, ftplib.Error) as error:
                    if not options.all:
                        raise
                    print(f'{title}: {error}', file=sys.stderr)
            for title, result in pending.items():
                try:
                    images[title] = result.result()
                except (ValueError, OSError) as error:
                    if not options.all:
                        raise
                    print(f'{title}: {error}', file=sys.stderr)
        if not images:
            raise ValueError('No public PlayStation artwork found')
        install(ftp, directory, images)
    for title, image in images.items():
        print(title, image)
    if options.all:
        print(f'Cached artwork for {len(images)} of {len(titles)} title IDs')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('error: ' + str(error).replace('\r', ' ').replace('\n', ' ')[:240], file=sys.stderr)
        sys.exit(1)
