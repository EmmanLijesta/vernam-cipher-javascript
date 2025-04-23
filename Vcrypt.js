"use strict";

/*
Code example by Engr. Emman Lijesta, 2025
Use freely in your own implementations.

Vernam Cipher is a secure encryption method as long as the key is not known.
The key must be in the backend or server side and hidden, even if the conversion
process is done on the frontend or client side. Make sure to use 64-digit
hexadecimal key at least for better security.

Code implementation intended to be like below for better readability, and modularity
for debugging.
*/

class Vernam {
    constructor (key, text) {
        this.key = key;
        this.text = text;
    }
    convert () {
        let results = [];
        for (let x in this.text) {
            results[x] = this.text[x].charCodeAt(0) ^ this.key[x % this.key.length].charCodeAt(0);
        }
        return results;
    }
}

class Vcrypt extends Vernam {
    constructor (key, text) {
        super(key, text);
    }
    encode () {
        let encoded = this.convert();
        let results = "";
        for (let x in encoded) {
            results += String.fromCharCode(encoded[x]);
        }
        return results;
    }
}

// removes code injections and produce a clean text
function sanitize (text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        "/": '&#x2F;',
    };
    const reg = /[&<>"'/]/ig;
    return text.replace(reg, (match)=>(map[match]));
}

// at least a 64-digit hexadecimal for security key, do not show the key on the frontend or client; this must be provided in the backend or server side
const Key = "3AF9309305FD127D7213FDF3CAC82FF1A8E49AA640525DAAE627716B286661CB"

// make sure to sanitize input text against code injections before encryption
let cipher = new Vcrypt (Key, sanitize("<script>alert('Hello');</script>The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog."));
let encoded = cipher.encode();
console.log(encoded);

// sanitizing text is no longer needed in the decoding process
cipher = new Vcrypt (Key, encoded);
let decoded = cipher.encode();
console.log(decoded);

/*
Encoded:
b^Tc3F(%RRK\G[f"^J.B_A@f+0V1a7PWf*P;AePV&o`XPD1(".PEXFXbTWN\D.2@a)OVBGXPf(PHNdS]V

Decoded (code injections sanitized during encoding):
&lt;script&gt;alert(&#x27;Hello&#x27;);&lt;&#x2F;script&gt;The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.
*/
