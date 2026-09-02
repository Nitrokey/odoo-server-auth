This module implements a vault for secrets and files using
end-to-end-encryption. The encryption and decryption happens in the
browser using a vault specific shared master key. The master keys are
encrypted using asymmetrically. For this the user has to enter a second
password on the first login or if he needs to access data in a vault.
The asymmetric keys are stored for a certain time in the browser
storage.

The server can never access the secrets with the information available.
Only people registered in the vault can decrypt or encrypt values in a
vault. The meta data isn't encrypted to be able to search/filter for
entries more easily.

Instead of a password the private key can be protected by a FIDO2
security key (e.g. a Nitrokey) using the WebAuthn PRF extension. This is
an additional method next to the password. An administrator can restrict
which protection methods are allowed for newly generated keys (password
only, security key only, or both).

A user can register multiple keys at the same time and every key can
unlock the vaults. This allows to combine e.g. a password protected key
with one or more security keys. Adding a key grants it access to all
vaults and inboxes the user can currently access. Removing a key revokes
its access and re-encrypts the vaults the user can write to with a fresh
master key so the removed key can no longer decrypt them. For read-only
vaults and inboxes the removed key's access is dropped but the data is not
re-encrypted. Each key can be given a label to tell them apart in the
"Vault Keys" list.

This modules requires a secure context for the browser to work properly
and therefore HTTPS support is required.

The [vault-recovery](https://github.com/fkantelberg/vault-recovery)
project focuses on disaster recovery in case of an incident to recover
secrets from old database backups or old exports.
