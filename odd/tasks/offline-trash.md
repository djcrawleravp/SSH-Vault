# Offline revocation trash for unreachable SSH servers

Feature branch: `feat/offline-trash`. Risk: item 1 (persistent vault format) + item 3 (existing delete contract must not change).

## Specs

S1. From the main menu, `Delete` must be usable when the remote server is unreachable or no longer
exists: on failure the user may move the connection to trash instead of being stuck.

S2. Trashed connections are hidden from the active server list and kept stored for 30 days.

S3. A trashed connection can be restored, recovering the same host/user/port/key pair and connecting
exactly as before.

S4. Expiry is evaluated when the application opens, using the stored date/time: entries older than 30
days are marked as expired and reported to the user. Expiry never purges anything.

S5. Final purge is manual: one confirmation keypress removes the record and its key material, and the
confirmation states what is lost and that encrypted backups still contain the key.

S6. Clock anomalies never cause expiry or purge: if the current time is earlier than the stored trash
timestamp, the entry is not expired and nothing is destroyed.

S7. Online delete behaviour is unchanged: same exit codes, same messages, same remote sequence
(probe -> revoke -> verify -> local cleanup).

S8. The vault stays `version: 1`. An older reader must still open a vault that contains trashed
entries; the new lifecycle fields are optional and non-destructive when absent.

## Tasks

| ID | Specs | Route | Commit |
|---|---|---|---|
| T1 | S1 S2 S8 | vault.py: optional `status`/`trashed_utc` fields + validation; session.py: `carry_lifecycle` keeps them across the staged-config round trip | e53c762 |
| T2 | S1 S2 S3 S4 S5 S6 | vault.py lifecycle helpers (trash, restore, purge, expired) + hermetic and real-KDBX tests | e53c762 |
| T3 | S1 S3 S4 S5 | launcher.py: trash screen with restore/purge, delete-failure offer, expiry report on launch + UI tests | d0b0bb9 |
| T4 | S7 | README section + no-regression test for the online delete argv contract | d0b0bb9 |

All four tasks are done on `feat/offline-trash`. Verification: `PATH="$PWD/.venv/bin:$PATH"
.venv/bin/python -m pytest -q app/tests` reports 121 passed, 2 skipped (the two skips are the
root-only permission-repair tests). `bash -n app/ssh_backend.sh` and `sh -n
app/remote_authorized_keys.sh`/`remote_permission_repair.sh` are clean. No backend shell file was
modified, so the remote sequence is unchanged.

## Log

L1 (user, verbatim): "Fijate que por ejemplo si estoy en el menu principal y quiero eliminar una
conexion con la opcion delete no puedo si es que ese servidor remoto no esta conectado o no tengo
acceso a el, no estoy seguro de que se pueda eliminar creo que la ultima vez lo intente y no pude,
requeria conexion y el server ese ya no existia me podes confirmar si se borra independientemente si
tengo o no conexion a ese server? solo confirmame"

L2 (user, verbatim): "que tal si primero las quita de la vista pero las mantiene guardadas por 30
dias y ya si no se vuelven a usar (de alguna manera que haya la forma de volver a añadirlas y
restaurar la conexion) se borren automaticamente esto que se haga automaticamente cuando abro la
aplicacion midiendo por fecha y hora no? que te parece esa manera?"

L3 (user, verbatim): "pero decime en pocas palabras y en corto por que tengo tdah que me propones"

L4 (orchestrator proposal the user accepted, verbatim): "Automático = esconder y avisar. Manual =
borrar de verdad." — user replied: "si perfecto arranquemos".

L5 (decision): silent clock-driven purge rejected because a wrong system clock (dead CMOS, cloned
VM, restored snapshot) would destroy every trashed entry at once, irreversibly and without undo, and
because `.vault-backups/` already retains the private key. Auto = hide + warn; purge = one explicit
keypress.

L6 (evidence): current delete path is network-gated at `app/ssh_backend.sh:892-895`
(`remote_probe_key`), unmarked entries are refused before that at `app/launcher.py:1217-1220`, and
`run_backend` takes an encrypted backup at `app/launcher.py:973-974` on every attempt.

L7 (evidence): `app/session.py:34-59` rebuilds `servers` entirely from the staged config, so any new
per-record field must be merged back explicitly or it is dropped on the next save.

L8 (decision): `last_used_utc` was dropped from the design. Expiry is measured only from
`trashed_utc`, so no per-connection write happens on every connect, and the window means exactly
"hidden for 30 days". Expiry is derived on read and never persisted.

L9 (decision, small scope expansion): trashed identities are excluded from `export_vault`. A
connection the user asked to hide must not reappear as an unencrypted private key in
`exported_keys/`. Pinned by `test_export_skips_trashed_identities`.

L10 (observed, pre-existing): 22 tests in the suite fail when `python3` on PATH is the system
interpreter, because the fake `ssh-keygen` stubs import `cryptography` and only `.venv` has it.
Running the suite with `PATH="$PWD/.venv/bin:$PATH"` makes all of them pass; this is an environment
detail, not a repository defect introduced here.

L11 (verification note): the independent-verifier launch was not admitted by the harness admission
gate, so the checks were executed inline: full suite, shell syntax, real-KDBX round trip through
`VaultStore.save`, a grep audit that the trash path contains no `subprocess`/`ssh`/`run_backend`
call, and a review of every `data['servers']` reader.
