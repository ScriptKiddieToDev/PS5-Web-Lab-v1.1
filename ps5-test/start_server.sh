#!/bin/sh
set -eu

LAB_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAB_PORT=${PS5_WEB_LAB_PORT:-8000}

if command -v ss >/dev/null 2>&1; then
  if ! LAB_LISTENERS=$(ss -H -ltn "sport = :${LAB_PORT}" 2>/dev/null); then
    echo "Impossibile verificare i listener con ss; avvio rifiutato per sicurezza." >&2
    exit 1
  fi
  if [ -n "$LAB_LISTENERS" ]; then
    echo "Porta TCP ${LAB_PORT} già in ascolto; non avvio un secondo server." >&2
    printf '%s\n' "$LAB_LISTENERS" >&2
    if command -v lsof >/dev/null 2>&1; then
      lsof -nP -iTCP:"${LAB_PORT}" -sTCP:LISTEN >&2 || true
    fi
    echo "Identifica e arresta manualmente il servizio corretto, poi riprova." >&2
    exit 1
  fi
elif command -v lsof >/dev/null 2>&1; then
  if lsof -nP -iTCP:"${LAB_PORT}" -sTCP:LISTEN; then
    echo "Porta TCP ${LAB_PORT} già in ascolto; non avvio un secondo server." >&2
    echo "Identifica e arresta manualmente il servizio corretto, poi riprova." >&2
    exit 1
  fi
else
  echo "ss/lsof non disponibili; il bind del server rileverà la porta occupata e non sostituirà il listener." >&2
fi

cd "$LAB_ROOT"
exec python3 "$LAB_ROOT/server.py"
