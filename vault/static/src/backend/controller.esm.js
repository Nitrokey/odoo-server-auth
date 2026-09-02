// © 2021-2024 Florian Kantelberg - initOS GmbH
// License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import {
    AlertDialog,
    ConfirmationDialog,
} from "@web/core/confirmation_dialog/confirmation_dialog";
import {FormController} from "@web/views/form/form_controller";
import {ListController} from "@web/views/list/list_controller";
import {_t} from "@web/core/l10n/translation";
import {patch} from "@web/core/utils/patch";
import {rpc} from "@web/core/network/rpc";
import {useService} from "@web/core/utils/hooks";

patch(FormController.prototype, {
    /**
     * Re-encrypt the key if the user is getting selected
     *
     * @private
     */
    async _vaultSendWizard() {
        const record = this.model.root;
        if (record.resModel !== "vault.send.wizard") return;

        if (!record.data.user_id || !record.data.public_keys) return;

        let publics = [];
        try {
            publics = JSON.parse(record.data.public_keys || "[]");
        } catch {
            publics = [];
        }

        const key = await this.vault.unwrap(record.data.key);
        const wrapped = await this.vault.wrap_for_public_keys(key, publics);
        await record.update({key_user: JSON.stringify(wrapped)});
    },

    /**
     * Re-encrypt the key if the entry is getting selected
     *
     * @private
     * @param {Object} record
     * @param {Object} changes
     * @param {Object} options
     */
    async _vaultStoreWizard() {
        const record = this.model.root;
        if (
            !record.data.entry_id ||
            !record.data.master_key ||
            !record.data.iv ||
            !record.data.secret_temporary
        )
            return;

        const key = await this.vault.unwrap_master_key(record.data.key);
        const secret = await this.vault_utils.sym_decrypt(
            key,
            record.data.secret_temporary,
            record.data.iv
        );
        const master_key = await this.vault.unwrap_master_key(record.data.master_key);

        await record.update({
            secret: await this.vault_utils.sym_encrypt(
                master_key,
                secret,
                record.data.iv
            ),
        });
    },

    /**
     * Add a new key in addition to the existing keys of the user
     *
     * @private
     * @param {Object} options passed to generate_keys (e.g. the key_type)
     */
    async _addVaultKey(options = {}) {
        const hasKey = await this.vault._check_database();
        if (!hasKey) {
            // No key yet, just initialize the first one
            await this.vault._initialize_keys();
            return;
        }

        // Unlock a key and use the uuid of the key we actually unlocked with
        const private_key = await this.vault.get_private_key();
        const unlockedUuid = this.vault.uuid;

        // Unwrap all master keys with the unlocked key
        const master_keys = await rpc("/vault/rights/get");
        const unwrapped_rights = {};
        for (const uuid in master_keys) {
            const wrapped = master_keys[uuid][unlockedUuid];
            if (wrapped)
                unwrapped_rights[uuid] = await this.vault_utils.unwrap(
                    wrapped,
                    private_key
                );
        }

        // Unwrap all inbox keys with the unlocked key
        const inbox_keys = await rpc("/vault/inbox/get");
        const unwrapped_inbox = {};
        for (const token in inbox_keys) {
            const wrapped = inbox_keys[token][unlockedUuid];
            if (wrapped)
                unwrapped_inbox[token] = await this.vault_utils.unwrap(
                    wrapped,
                    private_key
                );
        }

        // Generate the additional key
        await this.vault.generate_keys(options);

        // Re-wrap for every key of the user including the new one
        let result = {};
        for (const uuid in unwrapped_rights)
            result[uuid] = await this.vault.wrap_for_all(unwrapped_rights[uuid]);
        await rpc("/vault/rights/store", {keys: result});

        result = {};
        for (const token in unwrapped_inbox)
            result[token] = await this.vault.wrap_for_all(unwrapped_inbox[token]);
        await rpc("/vault/inbox/store", {keys: result});
    },

    /**
     * Remove a key and rotate the master keys of the affected vaults
     *
     * @private
     * @param {String} uuid the uuid of the key to remove
     */
    async _removeVaultKey(uuid) {
        // Rotate writable vaults excluding the removed key, then remove it
        const vaults = await this.model.orm.searchRead(
            "vault",
            [["allowed_write", "=", true]],
            ["id"],
            {limit: 0}
        );

        for (const vault of vaults)
            await this._reencryptVaultById(vault.id, false, true, uuid);

        await rpc("/vault/keys/remove", {uuid});
    },

    /**
     * Add a new key and grant it access to all vaults and inboxes
     *
     * @private
     */
    async _vaultAddKey() {
        if (!this.vault_utils.supported()) return;

        var self = this;

        this.dialogService.add(ConfirmationDialog, {
            body: _t("Do you really want to add a new key?"),
            confirmLabel: _t("Confirm"),
            cancelLabel: _t("Discard"),
            confirm: () => {
                return self
                    ._addVaultKey()
                    .then(async () => {
                        if (self.model && self.model.root) await self.model.root.load();

                        self.notification.add(_t("A new key has been added."), {
                            type: "success",
                        });
                    })
                    .catch((error) => {
                        // Surface WebAuthn/PRF errors instead of an uncaught
                        // rejection and keep the error name for diagnosis
                        let body = _t("An unexpected error occurred.");
                        if (error && error.message)
                            body = error.name
                                ? `${error.name}: ${error.message}`
                                : error.message;
                        else if (error && error.name) body = error.name;

                        self.dialogService.add(AlertDialog, {
                            title: _t("Failed to add the key"),
                            body,
                        });
                    });
            },
        });
    },

    /**
     * Remove the selected key and rotate the affected vaults
     *
     * @private
     */
    async _vaultRemoveKey() {
        if (!this.vault_utils.supported()) return;

        const root = this.model.root;
        const list = root.data.keys;
        const keys = list && list.records;
        if (!keys || keys.length <= 1) {
            this.dialogService.add(AlertDialog, {
                title: _t("Cannot remove the key"),
                body: _t("You can't remove your last key."),
            });
            return;
        }

        // The row the user clicked in the editable list is the edited record
        const edited = list.editedRecord;
        if (!edited) {
            this.dialogService.add(AlertDialog, {
                title: _t("Cannot remove the key"),
                body: _t("Please click the key you want to remove first."),
            });
            return;
        }

        const uuid = edited.data.uuid;
        var self = this;

        this.dialogService.add(ConfirmationDialog, {
            body: _t(
                "Do you really want to remove this key? The vaults will be " +
                    "re-encrypted to revoke its access."
            ),
            confirmLabel: _t("Confirm"),
            cancelLabel: _t("Discard"),
            confirm: () => {
                return self
                    ._removeVaultKey(uuid)
                    .then(async () => {
                        if (self.model && self.model.root) await self.model.root.load();

                        self.notification.add(_t("The key has been removed."), {
                            type: "success",
                        });
                    })
                    .catch((error) => {
                        let body = _t("An unexpected error occurred.");
                        if (error && error.message)
                            body = error.name
                                ? `${error.name}: ${error.message}`
                                : error.message;
                        else if (error && error.name) body = error.name;

                        self.dialogService.add(AlertDialog, {
                            title: _t("Failed to remove the key"),
                            body,
                        });
                    });
            },
        });
    },

    /**
     * Handle the deletion of a vault.right field in the vault view properly by
     * generating a new master key and re-encrypting everything in the vault to
     * deny any future access to the vault.
     *
     * @private
     * @param {Boolean} verify
     * @param {Boolean} force
     */
    async _reencryptVault(verify = false, force = false) {
        const record = this.model.root;
        return await this._reencryptVaultById(record.resId, verify, force);
    },

    /**
     * Rotate the master key of a vault and re-encrypt its data
     *
     * @private
     * @param {Number} vaultId
     * @param {Boolean} verify
     * @param {Boolean} force
     * @param {String} excludeUuid a user key uuid to exclude from re-wrapping
     */
    async _reencryptVaultById(
        vaultId,
        verify = false,
        force = false,
        excludeUuid = null
    ) {
        await this.vault._ensure_keys();

        const self = this;
        const master_key = await this.vault_utils.generate_key();

        // The vault master_key is a {user_key_uuid: wrapped} map for the user
        const vaults = await this.model.orm.searchRead(
            "vault",
            [["id", "=", vaultId]],
            ["master_key"],
            {limit: 1}
        );
        const current_key = await this.vault.unwrap_master_key(
            vaults.length ? vaults[0].master_key : false
        );

        // This stores the additional changes made to rights, fields, and files
        const changes = [];
        const problems = [];

        async function reencrypt(model, type) {
            // Load the entire data from the database
            const records = await self.model.orm.searchRead(
                model,
                [["vault_id", "=", vaultId]],
                ["iv", "value", "name", "entry_name"],
                {
                    context: {vault_reencrypt: true},
                    limit: 0,
                }
            );

            for (const rec of records) {
                const val = await self.vault_utils.sym_decrypt(
                    current_key,
                    rec.value,
                    rec.iv
                );
                if (val === null) {
                    const fixed_text = _t("of entry");
                    problems.push(
                        `${type} '${rec.name}' ${fixed_text} '${rec.entry_name}'`
                    );
                    continue;
                }

                const iv = self.vault_utils.generate_iv_base64();
                const encrypted = await self.vault_utils.sym_encrypt(
                    master_key,
                    val,
                    iv
                );

                changes.push({
                    id: rec.id,
                    model: model,
                    value: encrypted,
                    iv: iv,
                });
            }
        }

        this.ui.block();
        try {
            // Update the rights. Load without limit. Wrap the new master key for
            // every key of each user of the vault.
            const rights = await self.model.orm.searchRead(
                "vault.right",
                [["vault_id", "=", vaultId]],
                ["public_keys"],
                {limit: 0}
            );

            for (const right of rights) {
                let publics = [];
                try {
                    publics = JSON.parse(right.public_keys || "[]");
                } catch {
                    publics = [];
                }

                // Never re-wrap for the key being removed
                if (excludeUuid)
                    publics = publics.filter((entry) => entry.uuid !== excludeUuid);

                changes.push({
                    id: right.id,
                    model: "vault.right",
                    keys: await this.vault.wrap_for_public_keys(master_key, publics),
                });
            }

            // Re-encrypt vault.field and vault.file
            await reencrypt("vault.field", "Field");
            await reencrypt("vault.file", "File");

            if (problems.length && !force) {
                this.ui.unblock();

                this.dialogService.add(AlertDialog, {
                    title: _t("The following entries are broken:"),
                    body: problems.join("\n"),
                });
            }

            if (!verify) {
                await rpc("/vault/replace", {data: changes});
                if (this.model.root.resModel === "vault") await this.model.root.load();
            }
        } finally {
            this.ui.unblock();
        }
    },

    /**
     * Call the right importer in the import wizard onchange of the content field
     *
     * @private
     */
    async _vaultImportWizard() {
        const record = this.model.root;
        if (record.resModel !== "vault.import.wizard") return;

        // Try to import the file on the fly and store the compatible JSON in the
        // crypted_content field for the python backend
        const data = await this.importer.import(
            await this.vault.unwrap_master_key(record.data.master_key),
            record.data.name,
            atob(record.data.content)
        );

        if (data) await record.update({crypted_content: JSON.stringify(data)});
    },

    /**
     * Ensure that a vault.right has the shared master key wrapped for all keys
     *
     * @private
     * @param {Object} root
     * @param {Object} right
     */
    async _vaultEnsureRightKey(root, right) {
        if (!root.data.master_key || right.data.wrapped_keys) return;

        const params = {user_id: right.data.user_id[0]};
        const user = await rpc("/vault/public", params);

        if (!user || !user.public_keys) throw new TypeError("User has no public key");

        const master_key = await this.vault.unwrap_master_key(root.data.master_key);
        const wrapped = await this.vault.wrap_for_public_keys(
            master_key,
            user.public_keys
        );

        await right.update({wrapped_keys: JSON.stringify(wrapped)});
    },

    /**
     * Ensures that the master key of the vault and right lines are set
     *
     * @private
     */
    async _vaultEnsureKeys() {
        const root = this.model.root;
        if (root.resModel !== "vault") return;

        if (!root.data.master_key) {
            const wrapped = await this.vault.wrap_for_all(
                await this.vault_utils.generate_key()
            );
            await root.update({master_key: JSON.stringify(wrapped)});
        }

        if (root.data.right_ids)
            for (const right of root.data.right_ids.records)
                await this._vaultEnsureRightKey(root, right);
    },

    /**
     * Check the model of the form and call the above functions for the right case
     *
     * @private
     * @param {Object} button
     */
    async _vaultAction(button) {
        if (!this.vault_utils.supported()) {
            await this.dialogService.add(AlertDialog, {
                title: _t("Vault is not supported"),
                body: _t(
                    "A secure browser context is required. Please switch to " +
                        "https or contact your administrator"
                ),
            });
            return false;
        }

        const root = this.model.root;
        switch (root.resModel) {
            case "res.users":
                if (button && button.name === "vault_add_key") {
                    await this._vaultAddKey();
                    return false;
                } else if (button && button.name === "vault_remove_key") {
                    await this._vaultRemoveKey();
                    return false;
                }
                break;
            case "vault":
                if (button && button.name === "vault_reencrypt") {
                    await this._reencryptVault(false, true);
                    return false;
                } else if (button && button.name === "vault_verify") {
                    await this._reencryptVault(true, false);
                    return false;
                }

                await this._vaultEnsureKeys();
                break;

            case "vault.send.wizard":
                await this._vaultSendWizard();
                break;

            case "vault.store.wizard":
                await this._vaultStoreWizard();
                break;

            case "vault.import.wizard":
                await this._vaultImportWizard();
                break;
        }

        return true;
    },

    /**
     * Add the required rpc service to the controller which will be used to
     * get/store information from/to the vault controller
     */
    setup() {
        this.vault_utils = useService("vault_utils");
        if (this.props.resModel === "vault" && !this.vault_utils.supported()) {
            this.props.preventCreate = true;
            this.props.preventEdit = true;
        }

        super.setup();
        this.ui = useService("ui");
        this.vault = useService("vault");
        this.importer = useService("vault_import");
        this.notification = useService("notification");
    },

    /**
     * Hook into the relevant functions
     */
    async create() {
        const _super = super.create.bind(this);
        if (this.model.root.isDirty) await this._vaultAction();

        const ret = await _super(...arguments);
        return ret;
    },

    async onPagerUpdate() {
        const _super = super.onPagerUpdate.bind(this);
        if (this.model.root.isDirty) await this._vaultAction();
        return await _super(...arguments);
    },

    async saveButtonClicked() {
        const _super = super.saveButtonClicked.bind(this);
        if (this.model.root.isDirty) await this._vaultAction();
        return await _super(...arguments);
    },

    async discard() {
        const _super = super.discard.bind(this);
        if (this.model.root.resModel === "vault.entry")
            this.model.env.bus.trigger("ENCRYPT_FIELDS");
        return await _super(...arguments);
    },

    async beforeLeave() {
        const _super = super.beforeLeave.bind(this);
        if (this.model.root.isDirty) await this._vaultAction();
        return await _super(...arguments);
    },

    async beforeUnload() {
        const _super = super.beforeUnload.bind(this);
        if (this.model.root.isDirty) await this._vaultAction();
        return await _super(...arguments);
    },

    async beforeExecuteActionButton(clickParams) {
        const _super = super.beforeExecuteActionButton.bind(this);
        if (clickParams.special !== "cancel") {
            const _continue = await this._vaultAction(clickParams);
            if (!_continue) return false;
        }

        return await _super(...arguments);
    },
});

patch(ListController.prototype, {
    setup() {
        super.setup();
        this.vault_utils = useService("vault_utils");
        if (this.props.resModel === "vault" && !this.vault_utils.supported())
            this.props.showButtons = false;
    },
});
