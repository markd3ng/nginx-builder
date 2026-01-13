#!/bin/bash
set -e

# --- Configuration ---
# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

WORKDIR="/build"
SRC_DIR="${WORKDIR}/src"
OUTPUT_DIR="${WORKDIR}/output"
INSTALL_DIR="/tmp/nginx-build"

# PCRE2 & Zlib Versions (Stable)
PCRE2_VERSION="10.42"
ZLIB_VERSION="1.3.1"

mkdir -p ${SRC_DIR} ${OUTPUT_DIR} ${INSTALL_DIR}

# --- Helper Functions ---
log() {
    echo -e "${BLUE}[BUILD]${NC} $1"
}

get_latest_git_tag() {
    local repo=$1
    local filter=$2
    log "Finding latest tag for ${repo}..."
    git ls-remote --tags --refs --sort='v:refname' https://github.com/${repo}.git \
        | grep -oE "${filter}" | tail -n1
}

# --- 1. Resolve Versions ---
log "Resolving Versions (Rolling Release Mode)..."

# Nginx (Latest Release 1.x)
if [ -z "$NGINX_VERSION" ]; then
    NGINX_TAG=$(get_latest_git_tag "nginx/nginx" "release-[0-9.]+")
    NGINX_VERSION=${NGINX_TAG#release-}
fi
log "Target Nginx Version: ${GREEN}${NGINX_VERSION}${NC}"

# OpenSSL (Latest 3.x)
if [ -z "$OPENSSL_VERSION" ]; then
    OPENSSL_TAG=$(get_latest_git_tag "openssl/openssl" "openssl-3\.[0-9.]+")
    OPENSSL_VERSION=${OPENSSL_TAG#openssl-}
fi
log "Target OpenSSL Version: ${GREEN}${OPENSSL_VERSION}${NC}"

# --- 2. Download Sources ---
cd ${SRC_DIR}

clean_download() {
    local url=$1
    local dir=$2
    if [ -d "$dir" ]; then rm -rf "$dir"; fi
    log "Downloading $dir from $url..."
    case "$url" in
        *.git)
            git clone --depth 1 --recursive "$url" "$dir"
            ;;
        *)
            wget -qO- "$url" | tar xz
            # Handle tarball naming variations if needed
            ;;
    esac
}

# Core
clean_download "https://github.com/nginx/nginx.git" "nginx" 
# Switch nginx to specific tag
cd nginx && git fetch --tags && git checkout release-${NGINX_VERSION} && cd ..

clean_download "https://github.com/openssl/openssl.git" "openssl"
cd openssl && git fetch --tags && git checkout openssl-${OPENSSL_VERSION} && cd ..

# Deps (Tarballs for stability/compat with Nginx auto-build)
log "Downloading PCRE2 & Zlib..."
wget -qO- https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz | tar xz
wget -qO- https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.gz | tar xz

# Modules (Git Clones)
log "Downloading Modules..."
clean_download "https://github.com/vision5/ngx_devel_kit.git" "ngx_devel_kit"
clean_download "https://github.com/google/ngx_brotli.git" "ngx_brotli"
clean_download "https://github.com/openresty/luajit2.git" "luajit2"
clean_download "https://github.com/openresty/lua-nginx-module.git" "lua-nginx-module"
clean_download "https://github.com/openresty/set-misc-nginx-module.git" "set-misc-nginx-module"
clean_download "https://github.com/openresty/headers-more-nginx-module.git" "headers-more-nginx-module"
clean_download "https://github.com/tokers/zstd-nginx-module.git" "zstd-nginx-module"
clean_download "https://github.com/leev/ngx_http_geoip2_module.git" "ngx_http_geoip2_module"
clean_download "https://github.com/openresty/echo-nginx-module.git" "echo-nginx-module"
clean_download "https://github.com/slact/nchan.git" "nchan"
clean_download "https://github.com/arut/nginx-rtmp-module.git" "nginx-rtmp-module"
clean_download "https://github.com/aperezdc/ngx-fancyindex.git" "ngx-fancyindex"
clean_download "https://github.com/yaoweibin/ngx_http_substitutions_filter_module.git" "ngx_http_substitutions_filter_module"
clean_download "https://github.com/sto/ngx_http_auth_pam_module.git" "ngx_http_auth_pam_module"
clean_download "https://github.com/nginx-modules/ngx_cache_purge.git" "ngx_cache_purge"
clean_download "https://github.com/arut/nginx-dav-ext-module.git" "nginx-dav-ext-module"
clean_download "https://github.com/masterzen/nginx-upload-progress-module.git" "nginx-upload-progress-module"
clean_download "https://github.com/gnosek/nginx-upstream-fair.git" "nginx-upstream-fair"

# Lua Libs
clean_download "https://github.com/openresty/lua-resty-core.git" "lua-resty-core"
clean_download "https://github.com/openresty/lua-resty-lrucache.git" "lua-resty-lrucache"

# --- 3. Build LuaJIT (Static) ---
log "Building LuaJIT..."
cd ${SRC_DIR}/luajit2
make -j$(nproc)
make install # Installs to /usr/local
export LUAJIT_LIB=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.1

# --- 4. Configure & Build Nginx ---
log "Configuring Nginx..."
cd ${SRC_DIR}/nginx

# Disable strict error checking for deps that might have warnings
export CFLAGS="-Wno-error" 

./configure \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --lock-path=/var/run/nginx.lock \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
    --user=www-data \
    --group=www-data \
    --with-compat \
    --with-file-aio \
    --with-threads \
    --with-http_addition_module \
    --with-http_auth_request_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_mp4_module \
    --with-http_random_index_module \
    --with-http_realip_module \
    --with-http_secure_link_module \
    --with-http_slice_module \
    --with-http_ssl_module \
    --with-http_stub_status_module \
    --with-http_sub_module \
    --with-http_v2_module \
    --with-http_v3_module \
    --with-mail \
    --with-mail_ssl_module \
    --with-stream \
    --with-stream_realip_module \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-cc-opt="-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -fPIC -Wno-error" \
    --with-ld-opt="-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie" \
    --with-openssl=${SRC_DIR}/openssl \
    --with-pcre=${SRC_DIR}/pcre2-${PCRE2_VERSION} \
    --with-zlib=${SRC_DIR}/zlib-${ZLIB_VERSION} \
    --add-module=${SRC_DIR}/ngx_devel_kit \
    --add-module=${SRC_DIR}/ngx_brotli \
    --add-module=${SRC_DIR}/set-misc-nginx-module \
    --add-module=${SRC_DIR}/headers-more-nginx-module \
    --add-module=${SRC_DIR}/zstd-nginx-module \
    --add-module=${SRC_DIR}/ngx_http_geoip2_module \
    --add-module=${SRC_DIR}/echo-nginx-module \
    --add-module=${SRC_DIR}/nchan \
    --add-module=${SRC_DIR}/nginx-rtmp-module \
    --add-module=${SRC_DIR}/ngx-fancyindex \
    --add-module=${SRC_DIR}/ngx_http_substitutions_filter_module \
    --add-module=${SRC_DIR}/ngx_http_auth_pam_module \
    --add-module=${SRC_DIR}/ngx_cache_purge \
    --add-module=${SRC_DIR}/nginx-dav-ext-module \
    --add-module=${SRC_DIR}/nginx-upload-progress-module \
    --add-module=${SRC_DIR}/nginx-upstream-fair \
    --add-module=${SRC_DIR}/lua-nginx-module

log "Compiling Nginx..."
make -j$(nproc)
make install DESTDIR=${INSTALL_DIR}

# --- 5. Post-Install Setup ---
log "Installing Lua Libs..."
LUA_LIB_DIR="${INSTALL_DIR}/usr/local/share/lua/5.1"
mkdir -p ${LUA_LIB_DIR}
cp -r ${SRC_DIR}/lua-resty-core/lib/* ${LUA_LIB_DIR}/
cp -r ${SRC_DIR}/lua-resty-lrucache/lib/* ${LUA_LIB_DIR}/

# Verify
log "Verifying Build..."
${INSTALL_DIR}/usr/sbin/nginx -V

# --- 6. Package ---
log "Packaging..."
cd ${INSTALL_DIR}
TAR_NAME="nginx-custom.tar.gz"
tar -czvf ${OUTPUT_DIR}/${TAR_NAME} .

log "Build Complete: ${OUTPUT_DIR}/${TAR_NAME}"
