#!/usr/bin/env bash
# conda-forge PHP 8.5 (ext-sodium সহ; system PHP-তে sodium নেই)
exec "$HOME/.local/opt/mamba/envs/php/bin/php" "$(dirname "$0")/run.php" "$@"
