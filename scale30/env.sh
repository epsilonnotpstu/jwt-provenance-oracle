# source scale30/env.sh — user-local toolchains (installed without sudo, 2026-09-25)
export PATH="$HOME/.cargo/bin:$HOME/.local/opt/dotnet:$HOME/.local/bin:$HOME/.local/opt/mamba/envs/ruby/bin:$PATH"
export DOTNET_ROOT="$HOME/.local/opt/dotnet" DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
# versions at install: cargo 1.98.1, dotnet 8.0.425, maven 3.9.9, composer 2.10.3,
# ruby 3.3.6 (micromamba/conda-forge), go 1.27.0, java 21.0.12, php 8.5.10, node 22.23.2
