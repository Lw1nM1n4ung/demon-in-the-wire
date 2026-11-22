#!/bin/sh
# msfconsole wrapper for the Wire_Ghost worker image.
#
# The Metasploit Framework is copied out of the official
# metasploitframework/metasploit-framework image (see web_portal/Dockerfile).
# That image is Alpine — its Ruby is linked against musl libc — while the
# worker is Debian bookworm (glibc), so the framework cannot simply be run
# in place.  Instead the musl loader and the Alpine shared libraries are
# copied into a private prefix and the loader is invoked explicitly:
#
#   /opt/msf/alpine/lib/ld-musl-x86_64.so.1 --library-path <alpine libs> \
#       /opt/msf/ruby/bin/ruby /opt/msf/framework/msfconsole "$@"
#
# The environment mirrors the official image's own (GEM_HOME layout, no
# BUNDLE_PATH — setting BUNDLE_PATH makes Bundler look for the wrong
# directory layout).  The caller's working directory is deliberately
# preserved: the exploit task runs msfconsole with cwd=<temp dir> so any
# files a module writes land there.
set -e

MSF_ROOT="${MSF_ROOT:-/opt/msf/framework}"
MSF_BUNDLE="${MSF_BUNDLE:-/opt/msf/bundle}"
MSF_ALPINE="${MSF_ALPINE:-/opt/msf/alpine}"
MSF_RUBY="${MSF_RUBY:-/opt/msf/ruby/bin/ruby}"
MSF_LOADER="${MSF_LOADER:-${MSF_ALPINE}/lib/ld-musl-x86_64.so.1}"

GEM_HOME="${MSF_BUNDLE}"
BUNDLE_APP_CONFIG="${MSF_BUNDLE}"
BUNDLE_SILENCE_ROOT_WARNING=1
APP_HOME="${MSF_ROOT}"
MSF_ROOT="${MSF_ROOT}"
# Skip the Rails asset pipeline — we only need the console.
SKIP_RAILS_ASSETS=true
# The framework prints a warning about this on Ruby 3.x; harmless.
OPENSSL_CONF="${MSF_ROOT}/config/openssl.cnf"
PATH="${MSF_BUNDLE}/bin:${PATH}"

export GEM_HOME BUNDLE_APP_CONFIG BUNDLE_SILENCE_ROOT_WARNING APP_HOME MSF_ROOT
export SKIP_RAILS_ASSETS OPENSSL_CONF PATH

if [ ! -x "${MSF_LOADER}" ]; then
    echo "msfconsole wrapper: Metasploit runtime missing at ${MSF_LOADER}" >&2
    exit 127
fi

exec "${MSF_LOADER}" \
    --library-path "${MSF_ALPINE}/usr/lib" \
    "${MSF_RUBY}" "${MSF_ROOT}/msfconsole" "$@"
