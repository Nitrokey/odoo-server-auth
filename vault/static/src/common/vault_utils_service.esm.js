import {Component, onMounted, useRef, useState} from "@odoo/owl";
import {Dialog} from "@web/core/dialog/dialog";
import {_t} from "@web/core/l10n/translation";
import {registry} from "@web/core/registry";
import utils from "./utils.esm";

export class AskPassDialog extends Component {
    static template = "vault.AskPassDialog";
    static components = {Dialog};

    setup() {
        this.state = useState({
            // The protection method: "password", "keyfile" or "security_key"
            method: "password",
            password: "",
            confirm: "",
            error: "",
        });
        this.keyfileInput = useRef("keyfileInput");
    }

    /**
     * Resolve the dialog using a password
     *
     * @private
     */
    async _confirmPassword() {
        const {confirm} = this.props;
        const password = this.state.password;
        if (!password) {
            this.state.error = _t("Missing password");
            return;
        }
        if (confirm && this.state.confirm !== password) {
            this.state.error = _t("The passwords aren't matching");
            return;
        }
        this.props.onResolve({password, keyfile: null});
        this.props.close();
    }

    /**
     * Resolve the dialog using a keyfile
     *
     * @private
     */
    async _confirmKeyfile() {
        let keyfileContent = null;
        const input = this.keyfileInput.el;
        if (input && input.files && input.files[0]) {
            const file = input.files[0];
            const text = await file.text();
            keyfileContent = utils.fromBinary(text);
        }
        if (!keyfileContent) {
            this.state.error = _t("Please select a keyfile");
            return;
        }
        this.props.onResolve({password: "", keyfile: keyfileContent});
        this.props.close();
    }

    /**
     * Resolve the dialog using a security key. The WebAuthn ceremony happens
     * here so an error keeps the dialog open for another attempt.
     *
     * @private
     */
    async _confirmSecurityKey() {
        try {
            const credential = await this.props.registerSecurityKey();
            this.props.onResolve({
                credential_id: credential.credential_id,
                prf_salt: credential.prf_salt,
                prf: credential.prf,
            });
            this.props.close();
        } catch (error) {
            // Keep the dialog open so the user can retry or use a password
            this.state.error =
                error && error.message
                    ? error.message
                    : _t("Failed to register the security key");
        }
    }

    async onConfirm() {
        this.state.error = "";

        // When the security key isn't offered fall back to the password/keyfile
        // handling based on what the user filled in (unlock dialog).
        if (!this.props.allowSecurityKey) {
            const input = this.keyfileInput.el;
            if (!this.state.password && input && input.files && input.files[0])
                return this._confirmKeyfile();
            return this._confirmPassword();
        }

        if (this.state.method === "security_key") return this._confirmSecurityKey();
        if (this.state.method === "keyfile") return this._confirmKeyfile();
        return this._confirmPassword();
    }

    onCancel() {
        this.props.close();
    }
}

export class GeneratePassDialog extends Component {
    static template = "vault.GeneratePassDialog";
    static components = {Dialog};

    setup() {
        this.state = useState({
            length: 15,
            big: true,
            small: true,
            digits: true,
            special: false,
            password: "",
            error: "",
        });

        onMounted(() => this.generate());
    }

    generate() {
        let characters = "";
        if (this.state.big) characters += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        if (this.state.small) characters += "abcdefghijklmnopqrstuvwxyz";
        if (this.state.digits) characters += "0123456789";
        if (this.state.special) characters += "!?$%&/()[]{}|<>,;.:-_#+*\\";

        if (!characters) {
            this.state.password = "";
            this.state.error = _t("Select at least one character set");
            return;
        }

        this.state.error = "";
        this.state.password = utils.generate_secret(this.state.length, characters);
    }

    onOptionsChange() {
        this.generate();
    }

    onCancel() {
        this.props.close();
    }

    onConfirm() {
        if (!this.state.password) {
            this.state.error = _t("Missing password");
            return;
        }
        this.props.onResolve(this.state.password);
        this.props.close();
    }
}

export const vaultUtilsService = {
    dependencies: ["dialog"],

    start(env, {dialog}) {
        function askpass(title, options = {}) {
            const props = {
                title,
                confirm: Boolean(options.confirm),
                allowSecurityKey: Boolean(options.allowSecurityKey),
                registerSecurityKey: options.registerSecurityKey,
            };
            return new Promise((resolve) => {
                dialog.add(AskPassDialog, {
                    ...props,
                    onResolve: resolve,
                });
            });
        }

        function generate_pass(title, options = {}) {
            const props = {title, ...options};
            return new Promise((resolve) => {
                dialog.add(GeneratePassDialog, {
                    ...props,
                    onResolve: resolve,
                });
            });
        }

        return {
            ...utils,
            askpass,
            generate_pass,
        };
    },
};

registry.category("services").add("vault_utils", vaultUtilsService);
