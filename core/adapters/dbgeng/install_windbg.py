import urllib.request
import xml.dom.minidom
import zipfile
import tempfile
import binaryninja
from binaryninja.settings import Settings
import os


def check_install_ok(path):
    if not os.path.exists(os.path.join(path, 'amd64', 'dbgeng.dll')):
        return False

    if not os.path.exists(os.path.join(path, 'amd64', 'dbghelp.dll')):
        return False

    if not os.path.exists(os.path.join(path, 'amd64', 'dbgmodel.dll')):
        return False

    if not os.path.exists(os.path.join(path, 'amd64', 'dbgcore.dll')):
        return False

    if not os.path.exists(os.path.join(path, 'amd64', 'ttd', 'TTD.exe')):
        return False

    if not os.path.exists(os.path.join(path, 'amd64', 'ttd', 'TTDRecord.dll')):
        return False

    return True


def install_windbg():
    ttd_url = 'https://aka.ms/windbg/download'
    print('Downloading appinstaller from: %s...' % ttd_url)
    try:
        local_file, _ = urllib.request.urlretrieve(ttd_url)
    except Exception as e:
        print('Failed to download appinstaller file from %s' % ttd_url)
        print(e)
        return
    print('Successfully downloaded appinstaller')

    xml_doc = xml.dom.minidom.parse(local_file)
    try:
        msix_url = xml_doc.getElementsByTagName('MainBundle')[0].attributes['Uri'].value
    except Exception as e:
        print('Failed to parse XML')
        print(e)
        return

    print('Downloading MSIX bundle from: %s...' % msix_url)
    try:
        msix_file, _ = urllib.request.urlretrieve(msix_url)
    except Exception as e:
        print('Failed to download MSIX bundle from %s' % msix_url)
        print(e)
        return
    print('Successfully downloaded MSIX bundle')

    zip_file = zipfile.ZipFile(msix_file)
    temp_dir = tempfile.mkdtemp()
    inner_msix = zip_file.extract('windbg_win7-x64.msix', temp_dir)
    print('Extracted windbg_win7-x64 to %s' % inner_msix)

    install_target = os.path.join(binaryninja.user_directory(), 'windbg')
    print('Installing to: %s' % install_target)

    inner_zip = zipfile.ZipFile(inner_msix)
    inner_zip.extractall(install_target)

    if check_install_ok(install_target):
        print('WinDbg/TTD installed to %s!' % install_target)
    else:
        print('The WinDbg/TTD installation appears to be successful, but important files are missing from %s, '
              'and the TTD recording may not work properly.' % install_target)
        return

    x64dbgEngPath = os.path.join(install_target, 'amd64')
    if Settings().set_string("debugger.x64dbgEngPath", x64dbgEngPath):
        print('Please restart Binary Ninja to make the changes take effect!')
    else:
        print('Failed to set debugger.x64dbgEngPath to %s, the WinDbg/TTD installation is not being used' % (x64dbgEngPath))


install_windbg()
