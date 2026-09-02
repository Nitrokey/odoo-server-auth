::

  ┌───────┐ ┏━━━━━━━━━━━━━┓ ╔═══════════╗
  │ input │ ┃ unencrypted ┃ ║ encrypted ║
  └───────┘ ┗━━━━━━━━━━━━━┛ ╚═══════════╝

Vault
=====

Each vault stores entries with enrypted fields and files in a tree like structure. The access is controlled per vault. Every added user can read the secrets of a vault. Otherwise the users can receive permission to share the vault with other users, to write secrets in the vault, or to delete entries of the vault. The databases stores the public and password protected private key of each user. The password used for the private key is derived from a password entered by the user and should be different than the password used for the login. Keep in mind that the meta information like field name or file names aren't encrypted.

Shared-key encryption
=====================

To be able to securely share sensitive data between all users a shared-key encryption is used. All users share a common secret for each vault. This secret is encrypted by the public key of each user to grant access to the user by using the private key to restore the secret.

Multiple keys per user
======================

A user can have multiple keys and every key can unlock the vaults. The master key of a vault is therefore wrapped once per key of every user with access to the vault (stored in ``vault.right.key``). Inbox keys are wrapped the same way (stored in ``vault.inbox.wrap``). When a vault is shared with another user the master key is wrapped for every key of the recipient.

Adding a key unwraps every reachable master key and inbox key with a currently unlocked key and re-wraps them for the new key in addition to the existing keys. Removing a key rotates the master key of every affected vault, re-encrypts the data with the new master key and wraps it only for the remaining keys, so the removed key loses access. Removing the last remaining key is not allowed.

Removal only rotates the master key of vaults the user can write to. For vaults the user can only read and for inboxes the removed key's wrappings are simply dropped (which prevents any future use of that key), but the master key is not rotated because the user is not allowed to re-encrypt those vaults. As a consequence a party who both extracted the removed key and had already cached the master key of such a read-only vault could still decrypt its data. This matches the general trust model: read access already exposes the plaintext to the user, so sharing can not be revoked cryptographically from a vault the user does not control.

Encryption of master key
------------------------

::

  .                   ┏━━━━━━━━━━━━┓
                      ┃ Master key ┃
                      ┗━━━━━━━━━━━━┛
  ┏━━━━━━━━━━━━━━━━━┓       ┃
  ┃ User            ┃       ▼
  ┃                 ┃   ┏━━━━━━━━━┓
  ┃ ┏━━━━━━━━━━━━━┓ ┃   ┃ encrypt ┃      ╔════════════╗
  ┃ ┃ Public key  ┃━━━━▶┃ (RSA)   ┃━━━━━▶║ Master key ║
  ┃ ┗━━━━━━━━━━━━━┛ ┃   ┗━━━━━━━━━┛      ╚════════════╝
  ┃ ╔═════════════╗ ┃
  ┃ ║ Private key ║ ┃
  ┃ ╚═════════════╝ ┃
  ┗━━━━━━━━━━━━━━━━━┛

Decryption of master key
------------------------

::

  .   ┌──────────┐     ┏━━━━━━━━━━┓
      │ Password │━━━━▶┃ derive   ┃
      └──────────┘     ┃ (PBKDF2) ┃
                       ┗━━━━━━━━━━┛
                            ┃
  ┏━━━━━━━━━━━━━━━━━┓       ▼                          ╔════════════╗
  ┃ User            ┃  ┏━━━━━━━━━━┓                    ║ Master key ║
  ┃                 ┃  ┃ Password ┃                    ╚════════════╝
  ┃ ┏━━━━━━━━━━━━━┓ ┃  ┗━━━━━━━━━━┛                          ┃
  ┃ ┃ Public key  ┃ ┃       ┃                                ▼
  ┃ ┗━━━━━━━━━━━━━┛ ┃       ▼                           ┏━━━━━━━━━┓
  ┃ ╔═════════════╗ ┃   ┏━━━━━━━━┓   ┏━━━━━━━━━━━━━┓    ┃ decrypt ┃      ┏━━━━━━━━━━━━┓
  ┃ ║ Private key ║━━━━━┃ unlock ┃━━▶┃ Private key ┃━━━▶┃ (RSA)   ┃━━━━━▶┃ Master key ┃
  ┃ ╚═════════════╝ ┃   ┗━━━━━━━━┛   ┗━━━━━━━━━━━━━┛    ┗━━━━━━━━━┛      ┗━━━━━━━━━━━━┛
  ┗━━━━━━━━━━━━━━━━━┛

Security key (FIDO2)
--------------------

Instead of a password the private key can be protected by a FIDO2 security key
(e.g. a Nitrokey). The WebAuthn PRF extension (based on the CTAP2 hmac-secret
extension) is used to derive a stable secret from the authenticator for a fixed
salt. This secret is run through HKDF to obtain the AES key which wraps the
private key. Only the credential id and the salt are stored in the database;
the derived secret never leaves the browser. The AES/RSA envelope used for the
master key and the data is unchanged. This is an additional method next to the
password and an administrator can enforce it to forbid password protected keys.

Decryption of master key using a security key
----------------------------------------------

::

  .   ┌──────────────┐     ┏━━━━━━━━━━┓     ┏━━━━━━━━┓
      │ Security key │━━━━▶┃ WebAuthn ┃━━━━▶┃ derive ┃
      └──────────────┘     ┃ (PRF)    ┃     ┃ (HKDF) ┃
                           ┗━━━━━━━━━━┛     ┗━━━━━━━━┛
                                                ┃
                            ┌───────────────────┘
  ┏━━━━━━━━━━━━━━━━━┓       ▼                          ╔════════════╗
  ┃ User            ┃  ┏━━━━━━━━━━┓                    ║ Master key ║
  ┃                 ┃  ┃ Password ┃                    ╚════════════╝
  ┃ ┏━━━━━━━━━━━━━┓ ┃  ┗━━━━━━━━━━┛                          ┃
  ┃ ┃ Public key  ┃ ┃       ┃                                ▼
  ┃ ┗━━━━━━━━━━━━━┛ ┃       ▼                           ┏━━━━━━━━━┓
  ┃ ╔═════════════╗ ┃   ┏━━━━━━━━┓   ┏━━━━━━━━━━━━━┓    ┃ decrypt ┃      ┏━━━━━━━━━━━━┓
  ┃ ║ Private key ║━━━━━┃ unlock ┃━━▶┃ Private key ┃━━━▶┃ (RSA)   ┃━━━━━▶┃ Master key ┃
  ┃ ╚═════════════╝ ┃   ┗━━━━━━━━┛   ┗━━━━━━━━━━━━━┛    ┗━━━━━━━━━┛      ┗━━━━━━━━━━━━┛
  ┗━━━━━━━━━━━━━━━━━┛

Symmetric encryption of the data
================================

The symmetric cipher AES is used with the common master key to encrypt/decrypt the secrets of the vaults. The encryption parameter and encrypted data is stored in the database while everything else happens in the browser.

Encryption of data
------------------

::

  .               ┏━━━━━━━━━━━━┓
                  ┃ Master key ┃
                  ┗━━━━━━━━━━━━┛
                        ┃        ┏━━━━━━━━━━━━━━━━━━┓
                        ▼        ┃ Database         ┃
                   ┏━━━━━━━━━┓   ┃                  ┃
  ┏━━━━━━━━━━━━┓   ┃ encrypt ┃   ┃╔════════════════╗┃
  ┃ Plain text ┃━━▶┃ (AES)   ┃━━━▶║ Encrypted data ║┃
  ┗━━━━━━━━━━━━┛   ┗━━━━━━━━━┛   ┃╚════════════════╝┃
                        ┃        ┃┏━━━━━━━━━━━━━━━━┓┃
                        ┗━━━━━━━━▶┃ Parameters     ┃┃
                                 ┃┗━━━━━━━━━━━━━━━━┛┃
                                 ┗━━━━━━━━━━━━━━━━━━┛

Decryption of data
------------------

::

  .                    ┏━━━━━━━━━━━━┓
                       ┃ Master key ┃
                       ┗━━━━━━━━━━━━┛
  ┏━━━━━━━━━━━━━━━━━━┓       ┃
  ┃ Database         ┃       ▼
  ┃                  ┃   ┏━━━━━━━━━┓
  ┃╔════════════════╗┃   ┃ decrypt ┃   ┏━━━━━━━━━━━━┓
  ┃║ Encrypted data ║━━━▶┃ (AES)   ┃━━▶┃ Plain text ┃
  ┃╚════════════════╝┃   ┗━━━━━━━━━┛   ┗━━━━━━━━━━━━┛
  ┃┏━━━━━━━━━━━━━━━━┓┃       ▲
  ┃┃ Parameters     ┃━━━━━━━━┛
  ┃┗━━━━━━━━━━━━━━━━┛┃
  ┗━━━━━━━━━━━━━━━━━━┛

Inbox
=====

This allows an user to receive encrypted secrets by external or internal Odoo users. External users have to use either the owner specific inbox link from his preferences or the link of an already created inbox. The value is symmetrically encrypted. The key for the encryption is wrapped with the public key of the user of the inbox to grant the user the access to the key. Internal users can directly send a secret from a vault entry to another user who has enabled this feature. If a direct link is used the access counter and expiration time can block an overwrite.

Encryption of inbox
-------------------

::

  .                   ┏━━━━━━━━━━━━┓
                      ┃ Plain data ┃
                      ┗━━━━━━━━━━━━┛
  ┏━━━━━━━━━━━━━━━━━┓       ┃
  ┃ User            ┃       ▼
  ┃                 ┃   ┏━━━━━━━━━┓
  ┃ ┏━━━━━━━━━━━━━┓ ┃   ┃ encrypt ┃      ╔════════════════╗
  ┃ ┃ Public key  ┃━━━━▶┃ (RSA)   ┃━━━━━▶║ Encrypted data ║
  ┃ ┗━━━━━━━━━━━━━┛ ┃   ┗━━━━━━━━━┛      ╚════════════════╝
  ┃ ╔═════════════╗ ┃
  ┃ ║ Private key ║ ┃
  ┃ ╚═════════════╝ ┃
  ┗━━━━━━━━━━━━━━━━━┛

Decryption of inbox
-------------------

::

  .   ┌──────────┐     ┏━━━━━━━━━━┓
      │ Password │━━━━▶┃ derive   ┃
      └──────────┘     ┃ (PBKDF2) ┃
                       ┗━━━━━━━━━━┛
                            ┃
  ┏━━━━━━━━━━━━━━━━━┓       ▼                        ╔════════════════╗
  ┃ User            ┃  ┏━━━━━━━━━━┓                  ║ Encrypted data ║
  ┃                 ┃  ┃ Password ┃                  ╚════════════════╝
  ┃ ┏━━━━━━━━━━━━━┓ ┃  ┗━━━━━━━━━━┛                          ┃
  ┃ ┃ Public key  ┃ ┃       ┃                                ▼
  ┃ ┗━━━━━━━━━━━━━┛ ┃       ▼                           ┏━━━━━━━━━┓
  ┃ ╔═════════════╗ ┃   ┏━━━━━━━━┓   ┏━━━━━━━━━━━━━┓    ┃ decrypt ┃      ┏━━━━━━━━━━━━┓
  ┃ ║ Private key ║━━━━━┃ unlock ┃━━▶┃ Private key ┃━━━▶┃ (RSA)   ┃━━━━━▶┃ Plain data ┃
  ┃ ╚═════════════╝ ┃   ┗━━━━━━━━┛   ┗━━━━━━━━━━━━━┛    ┗━━━━━━━━━┛      ┗━━━━━━━━━━━━┛
  ┗━━━━━━━━━━━━━━━━━┛
