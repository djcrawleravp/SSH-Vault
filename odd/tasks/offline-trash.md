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
| T1 | S1 S2 S8 | vault.py: optional `status`/`trashed_utc`/`last_used_utc` fields + validation; session.py: preserve lifecycle fields across the staged-config round-trip | pending |
| T2 | S1 S2 S3 S4 S5 S6 | vault.py lifecycle helpers (trash, restore, purge, expired) + tests | pending |
| T3 | S1 S3 S4 S5 | launcher.py: trash view with restore/purge, delete-failure dialog offers trash, expiry banner on open + tests | pending |
| T4 | S7 | README section + non-regression tests for the online delete path | pending |

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
