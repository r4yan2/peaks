#!/usr/bin/env python3

import os
import shutil
from glob import glob
import hashlib
import tarfile
import zipfile
import requests

env = Environment(ENV=os.environ, CPPDEFINES=['GPG_COMPATIBLE', 'mpz_raw_64'])

BOOST_SEARCH_PREFIXES = ['/usr/local','/opt/local','lib/boost',]
BASEDIR = os.environ.get('PWD')
PREFIX_SCHEMA_DEFAULT = 'lib'
LIBDIR_SCHEMA_DEFAULT = 'lib/lib'
INCDIR_SCHEMA_DEFAULT = 'lib/include'
PREFIXDIR = os.path.join(BASEDIR, PREFIX_SCHEMA_DEFAULT)
LIBDIR = os.path.join(BASEDIR, LIBDIR_SCHEMA_DEFAULT)
INCDIR = os.path.join(BASEDIR, INCDIR_SCHEMA_DEFAULT)

def _download(url, filename):
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36'
    }
    response = requests.get(url, headers=headers)
    with open(filename, 'wb') as out:
        out.write(response.content)

def _check_sha(filename, expected):
    # BUF_SIZE is totally arbitrary, change for your app!
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!
    
    sha1 = hashlib.sha256()
    
    with open(filename, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha1.update(data)
    return sha1.hexdigest() == expected

def setup_gmp():

    ######### DOWNLOAD
    name = 'gmp-6.1.2'
    filename = name +  '.tar.bz2'
    if not os.path.exists(name):
        if not os.path.exists(filename):
            download_url = 'https://gmplib.org/download/gmp/'+filename
            _download(download_url, filename)
            if check and not _check_sha(filename, '5275bb04f4863a13516b2f39392ac5e272f5e1bb8057b18aec1c9b79d73d8fb2'):
                print('ERROR: could not verify %s downloaded from %s' % (filename, download_url))
                return False

        ######## DOWNLOAD PATCH
        patch = name + '.patch'
        patch_url = 'https://raw.githubusercontent.com/r4yan2/fastgcd/9605906557a397db0630d67dc7bbe5d60f2e2fc4/' + patch
        if not os.path.exists(patch):
            _download(patch_url, patch)
        if check and not _check_sha(patch, 'fe3b261f2d93ce2647f3bcb969b7a1c5e4db054a3b6eb02694f722bb2999c1b6'):
            print('ERROR: could not verify %s downloaded from %s' % (patch, patch_url))
            return False

        ####### EXTRACT
        with tarfile.open(filename) as archive:
            archive.extractall()

        ###### APPYING PATCH
        os.system('patch -d %s -p 1 < %s' % (name, patch))

    ##### COMPILING
    prefix = PREFIXDIR
    if build_type == 'release':
        cflags = '-march=native -Ofast'
    elif build_type == 'debug':
        cflags = '-march=native -g3 -O0 -ggdb -pg'
    else:
        cflags = '-O3 -march=x86-64 -mtune=generic'
    os.chdir(name)
    os.system('./configure --prefix="%s" CFLAGS="%s"' % (prefix, cflags))
    os.system('make -j%d' % (num_jobs,))
    if check:
        os.system('make check -j%d' % (num_jobs,))
    os.system('make install')

    ##### CLEANUP
    os.chdir('..')
    if build_type != 'debug':
        shutil.rmtree(name)

def setup_ntl():

    ######### DOWNLOAD
    name = 'ntl-10.5.0'
    filename = name +  '.tar.gz'
    if not os.path.exists(name):
        if not os.path.exists(filename):
            download_url = 'https://libntl.org/'+filename
            _download(download_url, filename)
            if check and not _check_sha(filename, 'b90b36c9dd8954c9bc54410b1d57c00be956ae1db5a062945822bbd7a86ab4d2'):
                print('ERROR: could not verify %s downloaded from %s' % (filename, download_url))
                return False
    
        ####### EXTRACT
        with tarfile.open(filename) as archive:
            archive.extractall()

    ##### COMPILING
    prefix = PREFIXDIR
    gmp_prefix = PREFIXDIR
    if build_type == 'release':
        cflags = '-O3 -fopenmp -D_GLIBCXX_PARALLEL -march=native'
        native = 'on'
        tune = 'auto'
    elif build_type == 'debug':
        cflags = '-g3 -O0 -march=native'
        native = 'on'
        tune = 'auto'
    else:
        cflags = '-O2 -march=x86-64 -mtune=generic'
        native = 'on'
        tune = 'auto'
    os.chdir(os.path.join(name,'src'))
    os.system('./configure NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on NTL_STD_CXX11=on CXXFLAGS="%s" NATIVE="%s" TUNE="%s" PREFIX="%s" GMP_PREFIX="%s"' % (cflags, native, tune, prefix, gmp_prefix))
    os.system('make -j%d' % (num_jobs,))
    if check:
        os.system('make check -j%d' % (num_jobs,))
    os.system('make install')

    ##### CLEANUP
    os.chdir('../..')
    if build_type != 'debug':
        shutil.rmtree(name)

def setup_cppcms():

    ######### DOWNLOAD
    name = 'cppcms-2.0.0.beta2'
    filename = name +  '.tar.bz2'
    if not os.path.exists(name):
        if not os.path.exists(filename):
            download_url = 'https://netix.dl.sourceforge.net/project/cppcms/cppcms/2.0.0-beta2/cppcms-2.0.0.beta2.tar.bz2'
            _download(download_url, filename)
            if check and not _check_sha(filename, '697031c7d141fdd215c6be5090b66e2106a63bb3e52f09ee8120e8efc6c08a21'):
                print('ERROR: could not verify %s downloaded from %s' % (filename, download_url))
                return False

        ####### EXTRACT
        with tarfile.open(filename) as archive:
            archive.extractall()

    ##### COMPILING
    prefix = PREFIXDIR
    os.chdir(name)
    if not os.path.isdir('build'):
        os.mkdir('build')
    os.chdir('build')
    os.system('cmake -DCMAKE_BUILD_TYPE=%s -DCMAKE_INSTALL_PREFIX=%s ..' % (build_type, prefix))
    os.system('make -j%d' % (num_jobs,))
    if check:
        os.system('make check -j%d' % (num_jobs,))
    os.system('make install')

    ##### CLEANUP
    os.chdir('../..')
    if build_type != 'debug':
        shutil.rmtree(name)

def setup_openpgp():

    ######### DOWNLOAD
    filename = 'peaks.zip'
    name = 'OpenPGP'
    prefix = PREFIXDIR
    gmp_prefix = PREFIXDIR
    gmp_lib = os.path.join(LIBDIR, 'libgmp.so')
    gmp_incl = INCDIR
    if not os.path.isdir(name):
        if not os.path.exists(filename):
            download_url = 'https://github.com/r4yan2/OpenPGP/archive/refs/heads/' + filename
            _download(download_url, filename)

            ####### EXTRACT
            with zipfile.ZipFile(filename, 'r') as archive:
                archive.extractall(name)

    ##### COMPILING
    os.chdir(name)
    if not os.path.isdir('build'):
        os.mkdir('build')
    os.chdir('build')
    os.system('cmake -DCMAKE_BUILD_TYPE="%s" -DCMAKE_INSTALL_PREFIX="%s" -DGMP_INCLUDES="%s" -DGMP_LIBRARIES="%s" -DGPG_COMPATIBLE=ON ..' % (build_type, prefix, gmp_incl, gmp_lib))
    os.system('make -j%d' % (num_jobs,))
    if check:
        os.system('make test')
    os.system('make install')

    ##### CLEANUP
    os.chdir('..')
    if build_type != 'debug':
        shutil.rmtree(name)

def fix_path(path):

    return str(os.path.abspath(path))

def CheckLib(lib):
    libItems = glob(os.path.join(BASEDIR, "lib/lib/", '%s*.*' % lib))
    return libItems

def FindBoost(context, prefixes=BOOST_SEARCH_PREFIXES):
    """Routine to auto-find boost header dir, lib dir, and library naming structure.
    """
    context.Message( 'Searching for boost libs and headers... ' )
    env = context.env

    BOOST_LIB_DIR = None
    BOOST_INCLUDE_DIR = None
    BOOST_APPEND = None
    env['BOOST_APPEND'] = str()
    search_lib = 'libboost_filesystem'

    # note: must call normpath to strip trailing slash otherwise dirname
    # does not remove 'lib' and 'include'
    prefixes.insert(0,os.path.dirname(os.path.normpath(env['BOOST_INCLUDES'])))
    prefixes.insert(0,os.path.dirname(os.path.normpath(env['BOOST_LIBS'])))
    for searchDir in prefixes:
        libItems = glob(os.path.join(searchDir, LIBDIR_SCHEMA_DEFAULT, '%s*.*' % search_lib))
        if not libItems:
            libItems = glob(os.path.join(searchDir, 'lib/%s*.*' % search_lib))
        incItems = glob(os.path.join(searchDir, 'include/boost*/'))
        if len(libItems) >= 1 and len(incItems) >= 1:
            BOOST_LIB_DIR = os.path.dirname(libItems[0])
            BOOST_INCLUDE_DIR = incItems[0].rstrip('boost/')
            shortest_lib_name = min(libItems, key=len)
            match = re.search(r'%s(.*)\..*' % search_lib, shortest_lib_name)
            if hasattr(match,'groups'):
                BOOST_APPEND = match.groups()[0]
            break

    msg = str()

    if BOOST_LIB_DIR:
        msg += '\nFound boost libs: %s' % BOOST_LIB_DIR
        env['BOOST_LIBS'] = BOOST_LIB_DIR
    elif not env['BOOST_LIBS']:
        env['BOOST_LIBS'] = '/usr/' + LIBDIR_SCHEMA_DEFAULT
        msg += '\nUsing default boost lib dir: %s' % env['BOOST_LIBS']
    else:
        msg += '\nUsing boost lib dir: %s' % env['BOOST_LIBS']

    if BOOST_INCLUDE_DIR:
        msg += '\nFound boost headers: %s' % BOOST_INCLUDE_DIR
        env['BOOST_INCLUDES'] = BOOST_INCLUDE_DIR
    elif not env['BOOST_INCLUDES']:
        env['BOOST_INCLUDES'] = '/usr/include'
        msg += '\nUsing default boost include dir: %s' % env['BOOST_INCLUDES']
    else:
        msg += '\nUsing boost include dir: %s' % env['BOOST_INCLUDES']

    if not env['BOOST_TOOLKIT'] and not env['BOOST_ABI'] and not env['BOOST_VERSION']:
        if BOOST_APPEND:
            msg += '\nFound boost lib name extension: %s' % BOOST_APPEND
            env['BOOST_APPEND'] = BOOST_APPEND
    else:
        # Creating BOOST_APPEND according to the Boost library naming order,
        # which goes <toolset>-<threading>-<abi>-<version>. See:
        #  http://www.boost.org/doc/libs/1_35_0/more/getting_started/unix-variants.html#library-naming
        append_params = ['']
        if env['BOOST_TOOLKIT']: append_params.append(env['BOOST_TOOLKIT'])
        if thread_flag: append_params.append(thread_flag)
        if env['BOOST_ABI']: append_params.append(env['BOOST_ABI'])
        if env['BOOST_VERSION']: append_params.append(env['BOOST_VERSION'])

        # Constructing the BOOST_APPEND setting that will be used to find the
        # Boost libraries.
        if len(append_params) > 1:
            env['BOOST_APPEND'] = '-'.join(append_params)
        msg += '\nFound boost lib name extension: %s' % env['BOOST_APPEND']

    env.AppendUnique(CPPPATH = fix_path(env['BOOST_INCLUDES']))
    env.AppendUnique(LIBPATH = fix_path(env['BOOST_LIBS']))
    ret = context.Result(msg)
    return ret


Help("""
    Type: 'scons peaks' to build the production program
        -jN build with <N> cpus
        -type=release|debug|profile to specify build type
""")

opts = Variables()

opts.AddVariables(
    # Boost variables
    # default is '/usr/include', see FindBoost method below
    ('BOOST_INCLUDES', 'Search path for boost include files', '',False),
    # default is '/usr/' + LIBDIR_SCHEMA, see FindBoost method below
    ('BOOST_LIBS', 'Search path for boost library files', '',False),
    ('BOOST_TOOLKIT','Specify boost toolkit, e.g., gcc41.','',False),
    ('BOOST_ABI', 'Specify boost ABI, e.g., d.','',False),
    ('BOOST_VERSION','Specify boost version, e.g., 1_35.','',False),
)

# implicit -j2 if not defined
num_jobs = ARGUMENTS.get('j') or int(os.environ.get('NUM_CPU', 2))
SetOption('num_jobs', num_jobs)

cflags = '-Wall -pipe -std=c++14'
build_type = ARGUMENTS.get('type')
build_type = build_type and build_type.lower() or 'release'
check = ARGUMENTS.get('check')

if not build_type or build_type == 'release':
    optflags = '-march=native -Ofast'
elif build_type == 'debug':
    optflags = '-march=native -g3 -rdynamic -O0 -ggdb'

if ARGUMENTS.get('profile'):
    optflags += ' -pg'

cflags += ' ' + optflags

libs = ['boost_system', 'boost_filesystem', 'boost_program_options', 'libOpenPGP', 'libntl', 'libgmp', 'pthread', 'curl', 'z', 'bz2', 'dl', 'stdc++', 'libcppcms', 'libbooster', 'mysqlcppconn']

opts.Update(env)
env.AppendUnique(CCFLAGS=cflags.split())

CUSTOM_LIBS = ['libgmp','libntl','libcppcms','libbooster','libOpenPGP']
BUILD_LIBS = {
    'libgmp': {
        'build': setup_gmp,
        },
    'libntl': {
        'build': setup_ntl,
        },
    'libcppcms': {
        'build': setup_cppcms,
        },
    'libOpenPGP': {
        'build': setup_openpgp,
        },
    }

conf = Configure(env, custom_tests={'FindBoost': FindBoost})

cpppath = ['#lib/include', '#src', '#src/cgi_handler']
env.AppendUnique(CPPPATH=cpppath)
env.AppendUnique(RPATH=LIBDIR)
env.AppendENVPath('LIB', LIBDIR)
env.AppendUnique(LIBPATH=LIBDIR)
if ARGUMENTS.get('profile'):
    env.AppendUnique(LINKFLAGS=['-pg'])


conf.FindBoost()
for lib in CUSTOM_LIBS:
    if not CheckLib(lib):
        BUILD_LIBS[lib]['build']()
for lib in libs:
    if lib.startswith('boost_') or lib in CUSTOM_LIBS:
        # already checked
        continue
    if not conf.CheckLib(lib):
        print('Did not find library %s, exiting!' % (lib,))
        Exit(1)

env.AppendUnique(LIBS=libs)
SConscript(dirs = 'src', name='SConscript', exports={'env':env, 'Glob':Glob, 'cpppath':cpppath, 'Program':env.Program, 'libpath': LIBDIR}, variant_dir='build', duplicate=0)
