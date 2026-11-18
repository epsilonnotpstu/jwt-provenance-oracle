#!/usr/bin/env bash
# user-local .NET 8 SDK (dotnet-install.sh, sudo ছাড়া)
D="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HOME/.local/opt/dotnet:$PATH" DOTNET_ROOT="$HOME/.local/opt/dotnet" DOTNET_CLI_TELEMETRY_OPTOUT=1
exec dotnet "$D/bin/Release/net8.0/Scale30Dotnet.dll" "$@"
