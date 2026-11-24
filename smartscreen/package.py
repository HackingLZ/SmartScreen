"""Appx/MSIX package-install reputation schema from the legacy Windows SDK.

Reads metadata only: no installation, signature verification, or local enforcement.
The recovered reader consumes one 4096-byte read from each footprint stream. This
is a named legacy profile, not a claim about every current Windows build.
"""
import base64
import copy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import uuid
import xml.etree.ElementTree as ET
import zipfile

ENDPOINT = 'https://checkappexec.microsoft.com/windows/shell/service/packageInstall/2'
READER = 'smartscreen-1.2.2312.1-prefix4096'
EVIDENCE = 'analysis/signature_catalog_expansion/native_package_hash.json'
FOOTPRINT = ('AppxManifest.xml', 'AppxBlockMap.xml', 'AppxSignature.p7x')
MAX_PART = 16*1024*1024
ARCHITECTURES = {'x86':0, 'arm':5, 'x64':9, 'neutral':11, 'arm64':12}


def _text(value, name, maximum=4096):
    if not isinstance(value,str) or not value or len(value)>maximum or '\0' in value:
        raise ValueError(name+' must be a bounded nonempty string without NUL')
    return value


def _manifest_identity(raw):
    if len(raw)>2*1024*1024 or b'<!DOCTYPE' in raw.replace(b'\0',b'').upper() or b'<!ENTITY' in raw.replace(b'\0',b'').upper():
        raise ValueError('Manifest exceeds size limit or declares XML entities')
    try:
        root=ET.fromstring(raw)
    except ET.ParseError as error:
        raise ValueError('Malformed AppxManifest.xml') from error
    if root.tag.rsplit('}',1)[-1]!='Package':
        raise ValueError('Only individual Appx/MSIX packages are supported, not bundles')
    items=[x for x in root if x.tag.rsplit('}',1)[-1]=='Identity']
    if len(items)!=1:
        raise ValueError('Expected exactly one package Identity')
    item=items[0].attrib
    for name in ('Name','Publisher','Version','ProcessorArchitecture'):
        _text(item.get(name),name)
    if not re.fullmatch(r'\d+\.\d+\.\d+\.\d+',item['Version']) or any(int(x)>65535 for x in item['Version'].split('.')):
        raise ValueError('Invalid package version')
    if item['ProcessorArchitecture'] not in ARCHITECTURES:
        raise ValueError('Unsupported package architecture')
    resource=item.get('ResourceId','')
    if not isinstance(resource,str) or len(resource)>4096 or '\0' in resource:
        raise ValueError('Invalid package resource ID')
    return {k:item[k] for k in ('Name','Publisher','Version','ProcessorArchitecture')} | {'ResourceId':resource}


def windows_package_full_name(identity):
    """Derive package full name through the documented OS API; does not install."""
    if os.name!='nt':
        raise ValueError('Provide full_name on non-Windows hosts; native identity derivation requires Windows')
    from ctypes import wintypes as w
    class PACKAGE_ID(ctypes.Structure):
        _fields_=[('reserved',w.DWORD),('architecture',w.DWORD),('version',ctypes.c_uint64),
                  ('name',w.LPWSTR),('publisher',w.LPWSTR),('resource',w.LPWSTR),('publisher_id',w.LPWSTR)]
    value=PACKAGE_ID()
    value.architecture=ARCHITECTURES[identity['ProcessorArchitecture']]
    parts=[int(x) for x in identity['Version'].split('.')]
    value.version=sum(x << (48-index*16) for index,x in enumerate(parts))
    value.name,value.publisher,value.resource=identity['Name'],identity['Publisher'],identity['ResourceId']
    get=ctypes.WinDLL('kernel32.dll').PackageFullNameFromId
    get.argtypes,get.restype=[ctypes.POINTER(PACKAGE_ID),ctypes.POINTER(w.DWORD),w.LPWSTR],w.LONG
    length=w.DWORD()
    status=get(ctypes.byref(value),ctypes.byref(length),None)
    if status!=122 or not 1<=length.value<=4096:
        raise ValueError('PackageFullNameFromId size query failed: '+str(status))
    buffer=ctypes.create_unicode_buffer(length.value)
    status=get(ctypes.byref(value),ctypes.byref(length),buffer)
    if status:
        raise ValueError('PackageFullNameFromId failed: '+str(status))
    return buffer.value


def _footprint(path):
    result={}
    if path.is_dir():
        root=path.resolve()
        for name in FOOTPRINT:
            candidate=path/name
            if candidate.is_symlink() or candidate.resolve().parent!=root or not candidate.is_file():
                raise ValueError('Missing or redirected package footprint: '+name)
            with candidate.open('rb') as stream:
                raw=stream.read(MAX_PART+1)
            if len(raw)>MAX_PART: raise ValueError('Package footprint exceeds limit: '+name)
            result[name]=raw
    else:
        try:
            with zipfile.ZipFile(path) as archive:
                infos=archive.infolist()
                if len(infos)>100000: raise ValueError('Too many package ZIP entries')
                for name in FOOTPRINT:
                    matches=[x for x in infos if x.filename.casefold()==name.casefold()]
                    if len(matches)!=1 or matches[0].filename!=name:
                        raise ValueError('Missing, duplicate, or case-ambiguous footprint: '+name)
                    info=matches[0]
                    if info.flag_bits & 1 or info.file_size>MAX_PART:
                        raise ValueError('Encrypted or oversized package footprint')
                    with archive.open(info) as stream:
                        raw=stream.read(MAX_PART+1)
                    if len(raw)!=info.file_size or len(raw)>MAX_PART:
                        raise ValueError('Package footprint size mismatch')
                    result[name]=raw
        except (zipfile.BadZipFile,NotImplementedError,RuntimeError) as error:
            raise ValueError('Unreadable Appx/MSIX ZIP: '+str(error)) from error
    return result


def extract_package(path, *, full_name=None):
    """Read individual package footprint files and build the named native reader's row."""
    path=Path(path)
    parts=_footprint(path)
    manifest=_manifest_identity(parts['AppxManifest.xml'])
    derived=windows_package_full_name(manifest) if os.name=='nt' else None
    if full_name is None: full_name=derived
    _text(full_name,'full_name')
    prefix='_'.join(manifest[x] for x in ('Name','Version','ProcessorArchitecture','ResourceId'))+'_'
    if not full_name.startswith(prefix) or not re.fullmatch('[a-z0-9]{13}',full_name[len(prefix):]):
        raise ValueError('Full name does not match manifest identity components')
    if derived is not None and derived!=full_name:
        raise ValueError('Full name does not match native publisher identity derivation')
    block,signature=parts['AppxBlockMap.xml'],parts['AppxSignature.p7x']
    if not block or not signature.startswith(b'PKCX'):
        raise ValueError('Expected a nonempty block map and PKCX package signature footprint')
    package={'fullName':full_name,'name':manifest['Name'],'publisher':manifest['Publisher'],
             'hash':base64.b64encode(hashlib.sha256(block[:4096]).digest()).decode(),
             'signature':base64.b64encode(signature[:4096]).decode()}
    return {'schema_version':1,'kind':'package_install_metadata','reader':READER,'path':str(path),
            'package':package,'manifest_identity':manifest,
            'full_name_source':'Windows PackageFullNameFromId' if derived else 'caller supplied; publisher ID not independently derived',
            'footprint':[{'name':name,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                          'wire_bytes':min(len(raw),4096) if name!='AppxManifest.xml' else None} for name,raw in parts.items()],
            'signature_trust':None,'schema_evidence':EVIDENCE,
            'limits':['Metadata extraction does not verify package signature or payload integrity.',
                      'The legacy reader hashes only the first4096 block-map bytes and includes at most4096 signature bytes.',
                      'Package hash is not a raw archive hash; installed directories do not establish original archive bytes.',
                      'Bundles and undocumented current-client reader changes are unsupported.']}


def _package_row(value):
    if not isinstance(value,dict) or set(value)!=set(('fullName','name','publisher','hash','signature')):
        raise ValueError('Package row must contain fullName,name,publisher,hash,signature')
    for key in ('fullName','name','publisher'):
        _text(value[key],key)
    try:
        digest=base64.b64decode(_text(value['hash'],'hash',64),validate=True)
        signature=base64.b64decode(_text(value['signature'],'signature',5464),validate=True)
    except (ValueError,TypeError) as error:
        raise ValueError('Package hash/signature must be bounded base64') from error
    if len(digest)!=32 or not 1<=len(signature)<=4096:
        raise ValueError('Package row exceeds native reader digest/signature bounds')
    return copy.deepcopy(value)


def package_payload(package, location, *, dependencies=None, location_type='uri', profile=None,
                    config=None, ux_enabled=False):
    """Build packageInstall/2; returned cloud result is separate from install enforcement."""
    from smartscreen import check_url, identity
    if location_type not in ('uri','path') or type(ux_enabled) is not bool:
        raise ValueError('Invalid package location type or ux_enabled')
    _text(location,'location',32768)
    if location_type=='uri': check_url(location)
    if profile is not None and not isinstance(profile,dict): raise ValueError('Identity must be an object')
    if config is not None and not isinstance(config,dict): raise ValueError('Config must be an object')
    if dependencies is None: dependencies=[]
    if not isinstance(dependencies,list) or len(dependencies)>128: raise ValueError('Dependencies must be a bounded array')
    result={'dependencies':[_package_row(x) for x in dependencies],'package':_package_row(package),
            'location':{'$type':location_type,'value':location},'identity':copy.deepcopy(profile) if profile is not None else identity(),
            'correlationId':str(uuid.uuid4()),'uxEnabled':ux_enabled}
    if config is not None: result['config']=copy.deepcopy(config)
    try:
        json.dumps(result,allow_nan=False)
    except (TypeError,ValueError) as error:
        raise ValueError('Package request must contain finite JSON values') from error
    return result


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path',type=Path)
    parser.add_argument('--full-name')
    args=parser.parse_args()
    try: print(json.dumps(extract_package(args.path,full_name=args.full_name),indent=2,allow_nan=False))
    except (OSError,ValueError) as error: parser.exit(2,str(error)+'\n')
