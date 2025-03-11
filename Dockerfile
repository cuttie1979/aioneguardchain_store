# Build stage
FROM python:3.12-alpine3.21 AS builder
WORKDIR /app

# Install build dependencies
RUN apk update && apk add --no-cache \
    cmake \
    build-base \
    linux-headers \
    gcompat \
    git \
    openssl-dev

# Build liboqs and liboqs-python
RUN CORES=$(nproc) && \
    echo "Detected $CORES cores." && \
    export CMAKE_BUILD_PARALLEL_LEVEL=$CORES && \
    export MAKEFLAGS="-j$CORES" && \
    git clone --depth=1 https://github.com/open-quantum-safe/liboqs && \
    cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON && \
    cmake --build liboqs/build --parallel $CORES && \
    cmake --build liboqs/build --target install && \
    git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python && \
    cd liboqs-python && \
    pip install --no-cache-dir . && \
    cd ..

# Runtime stage
FROM python:3.12-alpine3.21
LABEL authors="Laszlo Popovics"
LABEL vendor="AIvantGuard AG"
LABEL version="1.0.0"
WORKDIR /app

# Install only runtime dependencies
RUN apk update && apk add --no-cache \
    openssl  # Required if liboqs needs OpenSSL at runtime
ENV PYTHONPATH=/app

# Copy built artifacts from builder
COPY --from=builder /usr/local/lib/liboqs* /usr/local/lib/
COPY --from=builder /usr/local/include/oqs /usr/local/include/oqs/
COPY --from=builder /usr/local/lib/python3.12/site-packages/oqs /usr/local/lib/python3.12/site-packages/oqs/

# Copy application code and certificate
COPY aioneguard /app/aioneguard
COPY conf/rootCA.pem /app/rootCA.pem

# Final setup and cleanup
RUN pip install --upgrade pip setuptools certifi --no-cache-dir && \
    cat /app/rootCA.pem >> /usr/local/lib/python3.12/site-packages/certifi/cacert.pem && \
    rm -rf /app/rootCA.pem /root/.cache/pip /tmp/* /var/tmp/* /var/cache/apk/* && \
    mkdir -p /app/data /app/conf /app/logs

CMD ["python", "aioneguard/aioneguardchain/store/main.py", "start", "$INSTANCE_ID"]