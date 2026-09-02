// © 2021-2024 Florian Kantelberg - initOS GmbH
// License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import utils from "../common/utils.esm";

const data = {};
let key = false;
let iv = false;

const fields = [
    "keys",
    "iv",
    "publics",
    "encrypted",
    "secret",
    "encrypted_file",
    "filename",
    "secret_file",
    "submit",
];

function toggle_required(element, value) {
    if (value) element.setAttribute("required", "required");
    else element.removeAttribute("required");
}

// Encrypt the value and store it in the right input field
async function encrypt_and_store(value, target) {
    if (!utils.supported()) return false;

    // Find all the possible elements which are needed
    for (const id of fields) if (!data[id]) data[id] = document.getElementById(id);

    // We expect at least one public key here otherwise we can't procceed
    if (!data.publics.value) return;

    let publics = [];
    try {
        publics = JSON.parse(data.publics.value) || [];
    } catch {
        return;
    }
    if (!publics.length) return;

    // Create a new key if not already present and wrap it for every key of the
    // recipient so any of the recipient's keys can unwrap the secret
    if (!key) {
        key = await utils.generate_key();
        const wrapped = {};
        for (const entry of publics) {
            const public_key = await utils.load_public_key(entry.public);
            wrapped[entry.uuid] = await utils.wrap(key, public_key);
        }
        data.keys.value = JSON.stringify(wrapped);
    }

    // Create a new IV if not already present
    if (!iv) {
        iv = utils.generate_iv_base64();
        data.iv.value = iv;
    }

    // Encrypt the value symmetrically and store it in the field
    const val = await utils.sym_encrypt(key, value, iv);
    data[target].value = val;
    return Boolean(val);
}

document.getElementById("secret").onchange = async function () {
    if (!utils.supported()) return false;

    if (!this.value) return;

    const required = await encrypt_and_store(this.value, "encrypted");
    toggle_required(data.secret, required);
    toggle_required(data.secret_file, !required);
    data.submit.removeAttribute("disabled");
};

document.getElementById("secret_file").onchange = async function () {
    if (!utils.supported()) return false;

    if (!this.files.length) return;

    const file = this.files[0];
    const reader = new FileReader();
    let content = null;

    const promise = new Promise((resolve) => {
        reader.onload = () => {
            if (reader.result.indexOf(",") >= 0) content = reader.result.split(",")[1];
            resolve();
        };
    });

    reader.readAsDataURL(file);

    await promise;

    if (!content) return;

    const required = await encrypt_and_store(content, "encrypted_file");
    toggle_required(data.secret, !required);
    toggle_required(data.secret_file, required);
    data.filename.value = file.name;
    data.submit.removeAttribute("disabled");
};
