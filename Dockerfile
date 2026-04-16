# Invariant safety validation on NVIDIA Isaac Sim.
#
# Base: NVIDIA Isaac Sim 4.2 (includes Isaac Lab, CUDA, Python 3.10).
# Adds: Rust toolchain + Invariant binary.
#
# Build:
#   docker build -t invariant-isaac .
#
# Run locally (requires NVIDIA GPU + nvidia-docker):
#   docker run --gpus all -it invariant-isaac python isaac/campaign_runner.py --episodes 10
#
# On RunPod: use this as a custom Docker image, or build on-pod via the
# setup script (scripts/runpod_setup.sh).

# ---------------------------------------------------------------------------
# Stage 1: Build Invariant (Rust) in a slim builder
# ---------------------------------------------------------------------------
FROM rust:1.78-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY profiles/ profiles/

# Build release binary.
RUN cargo build --release --bin invariant && \
    strip target/release/invariant

# ---------------------------------------------------------------------------
# Stage 2: Isaac Sim runtime + Invariant binary
# ---------------------------------------------------------------------------
FROM nvcr.io/nvidia/isaac-sim:4.2.0

# Copy the Invariant binary from builder.
COPY --from=builder /build/target/release/invariant /usr/local/bin/invariant

# Copy profiles.
COPY profiles/ /opt/invariant/profiles/

# Copy Isaac Lab integration.
COPY isaac/ /opt/invariant/isaac/
COPY crates/invariant-sim/invariant_isaac_bridge.py /opt/invariant/isaac/

# Copy scripts.
COPY scripts/ /opt/invariant/scripts/

# Install Python dependencies (minimal — Isaac Sim provides most).
RUN pip install --no-cache-dir huggingface_hub

WORKDIR /opt/invariant

# Default: run the campaign runner.
ENTRYPOINT ["python", "isaac/campaign_runner.py"]
CMD ["--episodes", "100", "--steps", "200", "--profile", "ur10e_cnc_tending", "--output", "/results"]
