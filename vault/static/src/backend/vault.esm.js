// © 2021-2024 Florian Kantelberg - initOS GmbH
// License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import {_t} from "@web/core/l10n/translation";
import {registry} from "@web/core/registry";
import {rpc} from "@web/core/network/rpc";
import {session} from "@web/session";

// Database name on the browser
const Database = "vault";

const indexedDB =
    window.indexedDB ||
    window.mozIndexedDB ||
    window.webkitIndexedDB ||
    window.msIndexedDB ||
    window.shimIndexedDB;

// Expiration time of the vault store entries
const Expiration = 15 * 60 * 1000;

const vaultService = {
    dependencies: ["vault_utils"],
    start(env, {vault_utils}) {
        /**
         * Build the WebAuthn user information from the session
         *
         * @returns object with id, name and displayName
         */
        function webauthn_user() {
            return {
                id: String(session.uid || session.user_id || "vault-user"),
                name: session.username || "vault",
                displayName: session.name || session.username || "vault",
            };
        }

        /**
         * Register a new security key and return its credential information
         *
         * @returns object with credential_id and prf_salt
         */
        async function register_security_key() {
            if (!vault_utils.webauthn_supported())
                throw Error(_t("Security keys are not supported by the browser"));

            const prf_salt = vault_utils.toBase64(
                vault_utils.generate_bytes(vault_utils.PRFSaltLength)
            );
            const result = await vault_utils.security_key_register(
                webauthn_user(),
                prf_salt
            );
            return {
                credential_id: result.credential_id,
                prf_salt,
                // Raw PRF output if the browser evaluated it during registration
                prf: result.prf,
            };
        }

        /**
         * Ask the user how to protect the private key. Depending on the
         * configured allowed key types this either directly registers a
         * security key, only asks for a password, or shows a dialog offering
         * both a password and a "Use Security Key" option.
         *
         * @param {Object} options
         * @param {Boolean} options.confirm ask to confirm the password
         * @param {Boolean} options.allow_security_key offer the security key
         * @param {String} options.title the title shown in the dialog
         * @returns object {password, credential_id, prf_salt}
         */
        async function askpassword(options = {}) {
            const {
                confirm = false,
                allow_security_key = false,
                title = _t("Please enter the password for your private key"),
            } = options;

            let allowed = "password";
            if (allow_security_key) {
                const params = await rpc("/vault/keys/get");
                allowed = params.allowed_key_types || "all";
            }

            // The administrator enforces a security key. Skip the dialog and
            // register the credential directly.
            if (allowed === "security_key") {
                const credential = await register_security_key();
                return {
                    password: "",
                    credential_id: credential.credential_id,
                    prf_salt: credential.prf_salt,
                    prf: credential.prf,
                };
            }

            // Offer the security key option only if both types are allowed and
            // the browser supports WebAuthn with the PRF extension.
            const offer_security_key =
                allow_security_key &&
                allowed === "all" &&
                vault_utils.webauthn_supported();

            const askpass = await vault_utils.askpass(title, {
                confirm,
                allowSecurityKey: offer_security_key,
                registerSecurityKey: register_security_key,
            });

            // The user chose to protect the key with a security key
            if (askpass.credential_id && askpass.prf_salt) {
                return {
                    password: "",
                    credential_id: askpass.credential_id,
                    prf_salt: askpass.prf_salt,
                    prf: askpass.prf,
                    label: askpass.label || null,
                };
            }

            let password = askpass.password || "";
            if (askpass.keyfile) {
                password += await vault_utils.digest(
                    vault_utils.toBinary(askpass.keyfile)
                );
            }
            return {
                password,
                credential_id: null,
                prf_salt: null,
                label: askpass.label || null,
            };
        }

        class Vault {
            /**
             * Generate a new key pair and export to database and object store.
             *
             * @param {Object} options passed to the export to the database
             */
            async generate_keys(options = {}) {
                const opts =
                    typeof options === "string" ? {password: options} : {...options};

                this.keys = await vault_utils.generate_key_pair();
                this.time = new Date();

                if (!(await this._export_to_database(opts)))
                    throw Error(_t("Failed to export the keys to the database"));

                await this._export_to_store();
            }

            /**
             * Check if export to database is required due to key migration
             *
             * @private
             * @param {Object} options
             */
            async _check_key_migration(options = {}) {
                // Only password protected keys are migrated automatically. Security
                // key protected keys require a user gesture and can't be silently
                // re-exported.
                if (this.key_type && this.key_type !== "password") return;

                if (!this.version) await this._export_to_database(options);
                if (this.iterations < vault_utils.Derive.iterations)
                    await this._export_to_database(options);
            }

            /**
             * Lazy initialization of the keys which is not fully loading the keys
             * into the javascript but ensures that keys exist in the database to
             * to be loaded
             *
             * @private
             */
            async _initialize_keys() {
                // Get the uuid of the currently active keys from the database
                this.uuid = await this._check_database();
                if (this.uuid) {
                    // If the object store has the keys it's done
                    if (await this._import_from_store()) return;

                    // Otherwise an import from the database and export to the object store
                    // is needed
                    if (await this._import_from_database()) {
                        await this._export_to_store();
                        return true;
                    }

                    // This should be silent because it would influence the entire workflow
                    console.error("Failed to import the keys from the database");
                    return false;
                }

                // There are no keys in the database which means we have to generate them
                return await this.generate_keys();
            }

            /**
             * Ensure that the keys are available
             *
             * @private
             */
            async _ensure_keys() {
                // If the object store has the keys it's done
                if (this.uuid && !this.time) await this._import_from_store();

                // Check if the keys expired
                const now = new Date();
                if (this.time && now - this.time <= Expiration) return;

                // Keys expired means that we have to get them again
                this.keys = this.time = null;

                // Clear the object store first
                const store = await this._get_object_store();
                store.clear();

                // Import the keys from the database or generate them if missing
                if (!(await this._import_from_database())) {
                    if (await this._check_database())
                        throw Error(_t("Failed to import keys from database"));
                    return await this.generate_keys();
                }

                // Store the imported keys in the object store for the next calls
                if (!(await this._export_to_store()))
                    throw Error(_t("Failed to export keys to object store"));

                return;
            }

            /**
             * Get the private key and check if the keys expired
             *
             * @returns the private key of the user
             */
            async get_private_key() {
                await this._ensure_keys();
                return this.keys.privateKey;
            }

            /**
             * Get the public key and check if the keys expired
             *
             * @returns the public key of the user
             */
            async get_public_key() {
                await this._ensure_keys();
                return this.keys.publicKey;
            }

            /**
             * Open the indexed DB and return object store using promise
             *
             * @private
             * @returns a promise
             */
            _get_object_store() {
                return new Promise((resolve, reject) => {
                    const open = indexedDB.open(Database, 1);
                    open.onupgradeneeded = function () {
                        const db = open.result;
                        db.createObjectStore(Database, {keyPath: "id"});
                    };

                    open.onerror = function (event) {
                        reject(`error opening database ${event.target.errorCode}`);
                    };

                    open.onsuccess = function () {
                        const db = open.result;
                        const tx = db.transaction(Database, "readwrite");

                        resolve(tx.objectStore(Database));

                        tx.oncomplete = function () {
                            db.close();
                        };
                    };
                });
            }

            /**
             * Open the object store and extract the keys using the id
             *
             * @private
             * @param {String} uuid
             * @returns the result from the object store or false
             */
            async _get_keys(uuid) {
                const self = this;
                return new Promise((resolve, reject) => {
                    self._get_object_store().then((store) => {
                        const request = store.get(uuid);
                        request.onerror = function (event) {
                            reject(`error opening database ${event.target.errorCode}`);
                        };
                        request.onsuccess = function () {
                            resolve(request.result);
                        };
                    });
                });
            }

            /**
             * Check if the keys exist in the database
             *
             * @returns the uuid of a usable key or false
             */
            async _check_database() {
                const params = await rpc("/vault/keys/get");
                const keys = params.keys || [];
                return keys.length ? keys[0].uuid : false;
            }

            /**
             * Check if the keys exist in the store
             *
             * @private
             * @param {String} uuid
             * @returns if the keys are in the object store
             */
            async _check_store(uuid) {
                if (!uuid) return false;

                const result = await this._get_keys(uuid);
                return Boolean(result && result.keys);
            }

            /**
             * Import the keys from the indexed DB
             *
             * @private
             * @returns if the import from the object store succeeded
             */
            async _import_from_store() {
                const data = await this._get_keys(this.uuid);
                if (data) {
                    this.keys = data.keys;
                    this.time = data.time;
                    return true;
                }
                return false;
            }

            /**
             * Export the current keys to the indexed DB
             *
             * @private
             * @returns true
             */
            async _export_to_store() {
                const keys = {id: this.uuid, keys: this.keys, time: this.time};
                const store = await this._get_object_store();
                store.put(keys);
                return true;
            }

            /**
             * Export the key pairs to the backends. The private key is protected
             * either by a password or a security key. When no password is passed
             * explicitly (e.g. the silent migration) the user is asked how to
             * protect the key.
             *
             * @private
             * @param {Object} options with an optional password
             * @returns if the export to the database succeeded
             */
            async _export_to_database(options = {}) {
                // Compatibility: a bare string is treated as the password
                const opts =
                    typeof options === "string" ? {password: options} : options;

                // Generate salt for the user key
                this.salt = vault_utils.generate_bytes(vault_utils.SaltLength).buffer;
                this.iterations = vault_utils.Derive.iterations;
                // The version is only used for key/KDF migration and must not
                // distinguish between key types. The key_type field is used for
                // that instead.
                this.version = 1;

                // Wrap the private key with the master key of the user
                this.iv = vault_utils.generate_bytes(vault_utils.IVLength);

                let credential_id = null;
                let prf_salt = null;
                let prf = null;
                let pass = null;
                let password = opts.password;
                let label = opts.label || null;

                // Ask the user how to protect the key unless the password was
                // provided explicitly (e.g. the silent key migration).
                if (!password) {
                    const auth = await askpassword({
                        confirm: true,
                        allow_security_key: true,
                        title: _t("Protect your new private key"),
                    });
                    credential_id = auth.credential_id;
                    prf_salt = auth.prf_salt;
                    prf = auth.prf;
                    password = auth.password;
                    label = auth.label;
                }

                const key_type = credential_id ? "security_key" : "password";
                this.key_type = key_type;

                if (key_type === "security_key") {
                    // Reuse the PRF output from the registration ceremony if the
                    // browser provided it (Chromium) to avoid a second ceremony.
                    // Otherwise derive it with an additional assertion (Firefox).
                    pass = prf
                        ? await vault_utils.security_key_derive_key_from_prf(
                              prf,
                              prf_salt
                          )
                        : await vault_utils.security_key_derive_key(
                              credential_id,
                              prf_salt
                          );
                } else {
                    // Derive the user key from the password
                    pass = await vault_utils.derive_key(
                        password,
                        this.salt,
                        this.iterations
                    );
                }

                // Export the private key wrapped with the master key
                const private_key = await vault_utils.export_private_key(
                    await this.get_private_key(),
                    pass,
                    this.iv
                );

                // Export the public key
                const public_key = await vault_utils.export_public_key(
                    await this.get_public_key()
                );

                const params = {
                    public: public_key,
                    private: private_key,
                    iv: vault_utils.toBase64(this.iv),
                    iterations: this.iterations,
                    salt: vault_utils.toBase64(this.salt),
                    version: this.version,
                    key_type: key_type,
                    credential_id: credential_id,
                    prf_salt: prf_salt,
                    label: label,
                };

                // Export to the server
                const response = await rpc("/vault/keys/store", params);
                if (response) {
                    this.uuid = response;
                    return true;
                }

                console.error("Failed to export keys to database");
                return false;
            }

            /**
             * Import the keys from the backend and decrypt the private key
             *
             * @private
             * @returns if the import succeeded
             */
            async _import_from_database() {
                const params = await rpc("/vault/keys/get");
                const keys = params.keys || [];
                if (!keys.length) return false;

                // Select the key to unlock with. Prefer a security key the
                // browser can use, otherwise fall back to a password protected
                // key so the user only has to enter a password.
                let selected = keys.find(
                    (k) =>
                        k.key_type === "security_key" &&
                        vault_utils.webauthn_supported()
                );
                if (!selected)
                    selected = keys.find((k) => k.key_type !== "security_key");
                if (!selected) selected = keys[0];

                this.salt = vault_utils.fromBase64(selected.salt);
                this.iterations = selected.iterations;
                this.version = selected.version || 0;
                this.key_type = selected.key_type || "password";

                let pass = null;
                let raw_password = null;

                if (this.key_type === "security_key") {
                    // Derive the wrapping key from the security key
                    pass = await vault_utils.security_key_derive_key(
                        selected.credential_id,
                        selected.prf_salt
                    );
                } else {
                    // Request the password from the user and derive the user key
                    raw_password = (
                        await askpassword({
                            confirm: false,
                            title: _t("Unlock your private key"),
                        })
                    ).password;
                    let password = raw_password;

                    // Compatibility
                    if (!this.version) password = session.username + "|" + password;

                    pass = await vault_utils.derive_key(
                        password,
                        this.salt,
                        this.iterations
                    );
                }

                this.keys = {
                    publicKey: await vault_utils.load_public_key(selected.public),
                    privateKey: await vault_utils.load_private_key(
                        selected.private,
                        pass,
                        selected.iv
                    ),
                };

                this.time = new Date();
                this.uuid = selected.uuid;

                return true;
            }

            /**
             * Wrap the master key with the own public key
             *
             * @param {CryptoKey} master_key
             * @returns wrapped master key
             */
            async wrap(master_key) {
                return await vault_utils.wrap(master_key, await this.get_public_key());
            }

            /**
             * Wrap the master key with a public key given as string
             *
             * @param {CryptoKey} master_key
             * @param {String} public_key
             * @returns wrapped master key
             */
            async wrap_with(master_key, public_key) {
                const pub_key = await vault_utils.load_public_key(public_key);
                return await vault_utils.wrap(master_key, pub_key);
            }

            /**
             * Unwrap the master key with the own private key
             *
             * @param {CryptoKey} master_key
             * @returns unwrapped master key
             */
            async unwrap(master_key) {
                return await vault_utils.unwrap(
                    master_key,
                    await this.get_private_key()
                );
            }

            /**
             * Share a wrapped master key by unwrapping with own private key and wrapping with
             * another key
             *
             * @param {String} master_key
             * @param {String} public_key
             * @returns wrapped master key
             */
            async share(master_key, public_key) {
                const key = await this.unwrap(master_key);
                return await this.wrap_with(key, public_key);
            }

            /**
             * Pick the wrapping of the master key which matches the currently
             * unlocked key from a {user_key_uuid: wrapped} map (JSON string).
             *
             * @param {String} master_key JSON encoded map or a plain string
             * @returns the wrapped master key for the unlocked key or false
             */
            pick_master_key(master_key) {
                if (!master_key) return false;

                let map = null;
                try {
                    map = JSON.parse(master_key);
                } catch {
                    return master_key;
                }

                if (typeof map !== "object" || map === null) return master_key;
                return map[this.uuid] || false;
            }

            /**
             * Unwrap the master key from a {user_key_uuid: wrapped} map using the
             * currently unlocked key.
             *
             * @param {String} master_key JSON encoded map or a plain string
             * @returns the unwrapped master key
             */
            async unwrap_master_key(master_key) {
                return await this.unwrap(this.pick_master_key(master_key));
            }

            /**
             * Wrap a master key for every key of the current user.
             *
             * @param {CryptoKey} master_key
             * @returns a {user_key_uuid: wrapped} map
             */
            async wrap_for_all(master_key) {
                await this._ensure_keys();
                const params = await rpc("/vault/keys/get");
                const keys = params.keys || [];
                const result = {};
                for (const key of keys)
                    result[key.uuid] = await this.wrap_with(master_key, key.public);
                return result;
            }

            /**
             * Wrap a master key for every public key of another user.
             *
             * @param {CryptoKey} master_key
             * @param {Array} public_keys array of {uuid, public}
             * @returns a {user_key_uuid: wrapped} map
             */
            async wrap_for_public_keys(master_key, public_keys) {
                const result = {};
                for (const entry of public_keys || [])
                    result[entry.uuid] = await this.wrap_with(master_key, entry.public);
                return result;
            }
        }
        return new Vault();
    },
};

registry.category("services").add("vault", vaultService);
