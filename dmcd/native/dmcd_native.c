/*
 * LibreDM native hot paths: AES-CBC + HMAC-SHA256 (Encrypt-then-MAC)
 * and Telnet IAC filtering. Pure C via OpenSSL libcrypto.
 *
 * Build:  python3 dmcd/native/build.py
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <string.h>

/*
 * These sizes MUST stay in sync with dmcd/config.py
 * (IV_SIZE, MAC_SIZE, MAX_PACKET_SIZE, BLOCK_SIZE=16).
 * crypto.py also derives keys with the same "|KEY" / "|MAC" suffixes.
 */
#define IV_SIZE 16
#define MAC_SIZE 32
#define BLOCK_SIZE 16
#define MAX_PACKET (32 * 1024)

#define CTRL_ESC 255

/* ------------------------------------------------------------------ */
/* AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)                        */
/* ------------------------------------------------------------------ */

static int
aead_encrypt(const unsigned char *enc_key, int enc_key_len,
             const unsigned char *mac_key, int mac_key_len,
             const unsigned char *plain, int plain_len,
             unsigned char *out, int *out_len)
{
    unsigned char iv[IV_SIZE];
    unsigned char *ct = NULL;
    int ct_len = 0, pad_len, total, ret = 0;
    unsigned int mac_len = MAC_SIZE;
    EVP_CIPHER_CTX *ctx = NULL;

    if (enc_key_len != 32 || mac_key_len != 32)
        return -2; /* bad key size */
    if (plain_len < 0 || plain_len > MAX_PACKET)
        return -3;

    if (RAND_bytes(iv, IV_SIZE) != 1)
        return -4;

    pad_len = BLOCK_SIZE - (plain_len % BLOCK_SIZE);
    total = IV_SIZE + plain_len + pad_len + MAC_SIZE;
    ct = OPENSSL_malloc(plain_len + pad_len);
    if (!ct)
        return -5;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto done;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, iv) != 1)
        goto done;
    if (EVP_EncryptUpdate(ctx, ct, &ct_len, plain, plain_len) != 1)
        goto done;
    {
        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx, ct + ct_len, &final_len) != 1)
            goto done;
        ct_len += final_len;
    }

    /* body = iv || ciphertext */
    memcpy(out, iv, IV_SIZE);
    memcpy(out + IV_SIZE, ct, ct_len);

    if (HMAC(EVP_sha256(), mac_key, mac_key_len, out, IV_SIZE + ct_len,
             out + IV_SIZE + ct_len, &mac_len) == NULL)
        goto done;

    *out_len = IV_SIZE + ct_len + MAC_SIZE;
    ret = 0;

done:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_free(ct);
    return ret;
}

static int
aead_decrypt(const unsigned char *enc_key, int enc_key_len,
             const unsigned char *mac_key, int mac_key_len,
             const unsigned char *data, int data_len,
             unsigned char *out, int *out_len)
{
    unsigned char expected[MAC_SIZE];
    unsigned int mac_len = MAC_SIZE;
    const unsigned char *iv, *ct, *mac;
    int ct_len, pt_len = 0, ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;

    if (enc_key_len != 32 || mac_key_len != 32)
        return -2;
    if (data_len < IV_SIZE + BLOCK_SIZE + MAC_SIZE)
        return -3;

    iv = data;
    mac = data + data_len - MAC_SIZE;
    ct = data + IV_SIZE;
    ct_len = data_len - IV_SIZE - MAC_SIZE;
    if (ct_len % BLOCK_SIZE != 0)
        return -3;

    /* Encrypt-then-MAC: verify before touching ciphertext. */
    if (HMAC(EVP_sha256(), mac_key, mac_key_len, data, data_len - MAC_SIZE,
             expected, &mac_len) == NULL)
        return -4;
    if (CRYPTO_memcmp(expected, mac, MAC_SIZE) != 0)
        return -6; /* HMAC mismatch */

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -5;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, iv) != 1)
        goto done;
    if (EVP_DecryptUpdate(ctx, out, &pt_len, ct, ct_len) != 1)
        goto done;
    {
        int final_len = 0;
        /* EVP_DecryptFinal_ex validates and strips PKCS7 padding. */
        if (EVP_DecryptFinal_ex(ctx, out + pt_len, &final_len) != 1) {
            ret = -7; /* bad padding */
            goto done;
        }
        pt_len += final_len;
    }

    *out_len = pt_len;
    ret = 0;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Python wrappers                                                     */
/* ------------------------------------------------------------------ */

static PyObject *
py_aead_encrypt(PyObject *self, PyObject *args)
{
    const unsigned char *enc_key, *mac_key, *plain;
    Py_ssize_t enc_key_len, mac_key_len, plain_len;
    unsigned char *out;
    int out_len = 0, rc;
    PyObject *result;

    if (!PyArg_ParseTuple(args, "y#y#y#",
                          &enc_key, &enc_key_len,
                          &mac_key, &mac_key_len,
                          &plain, &plain_len))
        return NULL;

    out = PyMem_Malloc(plain_len + IV_SIZE + BLOCK_SIZE + MAC_SIZE + 16);
    if (!out)
        return PyErr_NoMemory();

    rc = aead_encrypt(enc_key, (int)enc_key_len, mac_key, (int)mac_key_len,
                      plain, (int)plain_len, out, &out_len);
    if (rc != 0) {
        PyMem_Free(out);
        if (rc == -2)
            return PyErr_Format(PyExc_ValueError, "keys must be 32 bytes");
        return PyErr_Format(PyExc_RuntimeError, "encrypt failed (%d)", rc);
    }
    result = PyBytes_FromStringAndSize((const char *)out, out_len);
    PyMem_Free(out);
    return result;
}

static PyObject *
py_aead_decrypt(PyObject *self, PyObject *args)
{
    const unsigned char *enc_key, *mac_key, *data;
    Py_ssize_t enc_key_len, mac_key_len, data_len;
    unsigned char *out;
    int out_len = 0, rc;
    PyObject *result;

    if (!PyArg_ParseTuple(args, "y#y#y#",
                          &enc_key, &enc_key_len,
                          &mac_key, &mac_key_len,
                          &data, &data_len))
        return NULL;

    out = PyMem_Malloc(data_len + 1);
    if (!out)
        return PyErr_NoMemory();

    rc = aead_decrypt(enc_key, (int)enc_key_len, mac_key, (int)mac_key_len,
                      data, (int)data_len, out, &out_len);
    if (rc != 0) {
        PyMem_Free(out);
        if (rc == -6)
            return PyErr_Format(PyExc_ValueError, "HMAC verification failed");
        if (rc == -7)
            return PyErr_Format(PyExc_ValueError, "bad padding");
        return PyErr_Format(PyExc_ValueError, "decrypt failed (%d)", rc);
    }
    result = PyBytes_FromStringAndSize((const char *)out, out_len);
    PyMem_Free(out);
    return result;
}

/* ------------------------------------------------------------------ */
/* Telnet IAC filter                                                   */
/* ------------------------------------------------------------------ */

/*
 * Strip Telnet IAC negotiations from `data`.
 * Returns (payload, replies) where replies are WONT/WILL answers.
 */
static PyObject *
filter_telnet(PyObject *self, PyObject *args)
{
    const unsigned char *data;
    Py_ssize_t n, i = 0;
    unsigned char *out = NULL, *rep = NULL;
    Py_ssize_t out_len = 0, rep_len = 0;
    PyObject *result = NULL, *py_out = NULL, *py_rep = NULL;

    if (!PyArg_ParseTuple(args, "y#", &data, &n))
        return NULL;

    out = PyMem_Malloc(n ? n : 1);
    rep = PyMem_Malloc(n ? (n * 3 + 8) : 8);
    if (!out || !rep) {
        PyMem_Free(out);
        PyMem_Free(rep);
        return PyErr_NoMemory();
    }

    while (i < n) {
        unsigned char b = data[i];
        if (b != CTRL_ESC) {
            out[out_len++] = b;
            i++;
            continue;
        }
        if (i + 1 >= n)
            break;
        unsigned char cmd = data[i + 1];
        if (cmd == CTRL_ESC) {
            out[out_len++] = CTRL_ESC;
            i += 2;
        } else if (cmd == 253 && i + 2 < n) { /* DO opt */
            unsigned char opt = data[i + 2];
            if (opt == 1) {            /* ECHO -> WILL ECHO */
                rep[rep_len++] = 255; rep[rep_len++] = 251; rep[rep_len++] = 1;
            } else if (opt == 3) {     /* SGA -> WILL SGA */
                rep[rep_len++] = 255; rep[rep_len++] = 251; rep[rep_len++] = 3;
            } else if (opt == 24) {    /* TTYPE -> WONT TTYPE */
                rep[rep_len++] = 255; rep[rep_len++] = 252; rep[rep_len++] = 24;
            }
            i += 3;
        } else if (cmd == 251 && i + 2 < n) { /* WILL opt */
            unsigned char opt = data[i + 2];
            if (opt == 3) {            /* WILL SGA -> DO SGA */
                rep[rep_len++] = 255; rep[rep_len++] = 253; rep[rep_len++] = 3;
            }
            i += 3;
        } else if (cmd == 251 || cmd == 252 || cmd == 253 || cmd == 254) {
            i += 3;
        } else if (cmd == 250) {       /* SB ... SE */
            i += 2;
            while (i < n) {
                if (data[i] == CTRL_ESC && i + 1 < n && data[i + 1] == 240) {
                    i += 2;
                    break;
                }
                i++;
            }
        } else {
            i += 2;
        }
    }

    py_out = PyBytes_FromStringAndSize((const char *)out, out_len);
    py_rep = PyBytes_FromStringAndSize((const char *)rep, rep_len);
    if (py_out && py_rep)
        result = PyTuple_Pack(2, py_out, py_rep);
    Py_XDECREF(py_out);
    Py_XDECREF(py_rep);
    PyMem_Free(out);
    PyMem_Free(rep);
    return result;
}

/* ------------------------------------------------------------------ */
/* squeeze_backspace                                                   */
/* ------------------------------------------------------------------ */

static PyObject *
squeeze_backspace(PyObject *self, PyObject *args)
{
    const unsigned char *data;
    Py_ssize_t n, i = 0, out_len = 0;
    unsigned char *out;
    PyObject *result;

    if (!PyArg_ParseTuple(args, "y#", &data, &n))
        return NULL;

    out = PyMem_Malloc(n ? n : 1);
    if (!out)
        return PyErr_NoMemory();

    while (i < n) {
        unsigned char b = data[i];
        if (b == 8 || b == 127) {
            out[out_len++] = b;
            if (i + 1 < n && (data[i + 1] == 8 || data[i + 1] == 127) && data[i] != data[i + 1])
                i += 2;
            else
                i += 1;
        } else {
            out[out_len++] = b;
            i += 1;
        }
    }

    result = PyBytes_FromStringAndSize((const char *)out, out_len);
    PyMem_Free(out);
    return result;
}

/* ------------------------------------------------------------------ */
/* PBKDF2-SHA256                                                       */
/* ------------------------------------------------------------------ */

static PyObject *
pbkdf2_sha256(PyObject *self, PyObject *args)
{
    const char *password;
    Py_ssize_t password_len;
    const unsigned char *salt;
    Py_ssize_t salt_len;
    unsigned int iterations;
    unsigned char dk[32];
    PyObject *result;

    if (!PyArg_ParseTuple(args, "y#y#I", &password, &password_len,
                          &salt, &salt_len, &iterations))
        return NULL;
    if (iterations < 1 || iterations > 10000000)
        return PyErr_Format(PyExc_ValueError, "iterations out of range");

    if (PKCS5_PBKDF2_HMAC(password, (int)password_len, salt, (int)salt_len,
                          (int)iterations, EVP_sha256(), 32, dk) != 1)
        return PyErr_Format(PyExc_RuntimeError, "PBKDF2 failed");

    result = PyBytes_FromStringAndSize((const char *)dk, 32);
    return result;
}

/* ------------------------------------------------------------------ */
/* SHA-256 / HMAC-SHA256 / session KDF                                 */
/* ------------------------------------------------------------------ */

static PyObject *
py_sha256(PyObject *self, PyObject *args)
{
    const unsigned char *data;
    Py_ssize_t n;
    unsigned char out[SHA256_DIGEST_LENGTH];

    if (!PyArg_ParseTuple(args, "y#", &data, &n))
        return NULL;
    SHA256(data, (size_t)n, out);
    return PyBytes_FromStringAndSize((const char *)out, SHA256_DIGEST_LENGTH);
}

static PyObject *
py_hmac_sha256(PyObject *self, PyObject *args)
{
    const unsigned char *key, *data;
    Py_ssize_t key_len, data_len;
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int out_len = 0;

    if (!PyArg_ParseTuple(args, "y#y#", &key, &key_len, &data, &data_len))
        return NULL;
    if (HMAC(EVP_sha256(), key, (int)key_len, data, (size_t)data_len, out, &out_len) == NULL)
        return PyErr_Format(PyExc_RuntimeError, "HMAC failed");
    return PyBytes_FromStringAndSize((const char *)out, (Py_ssize_t)out_len);
}

static PyObject *
py_derive_session_keys(PyObject *self, PyObject *args)
{
    const unsigned char *shared;
    Py_ssize_t shared_len;
    unsigned char buf[1024];
    unsigned char enc[SHA256_DIGEST_LENGTH], mac[SHA256_DIGEST_LENGTH];
    PyObject *a, *b, *result;

    if (!PyArg_ParseTuple(args, "y#", &shared, &shared_len))
        return NULL;
    if (shared_len < 0 || shared_len > (Py_ssize_t)(sizeof(buf) - 4))
        return PyErr_Format(PyExc_ValueError, "shared secret too long");

    /* enc_key = SHA256(shared || "|KEY") */
    memcpy(buf, shared, (size_t)shared_len);
    memcpy(buf + shared_len, "|KEY", 4);
    SHA256(buf, (size_t)shared_len + 4, enc);

    /* mac_key = SHA256(shared || "|MAC") */
    memcpy(buf + shared_len, "|MAC", 4);
    SHA256(buf, (size_t)shared_len + 4, mac);

    a = PyBytes_FromStringAndSize((const char *)enc, SHA256_DIGEST_LENGTH);
    b = PyBytes_FromStringAndSize((const char *)mac, SHA256_DIGEST_LENGTH);
    if (!a || !b) {
        Py_XDECREF(a);
        Py_XDECREF(b);
        return NULL;
    }
    result = PyTuple_Pack(2, a, b);
    Py_DECREF(a);
    Py_DECREF(b);
    return result;
}

/* ------------------------------------------------------------------ */
/* Diffie-Hellman (RFC 3526 MODP groups, g = 2)                        */
/* ------------------------------------------------------------------ */

static BIGNUM *
bn_from(const unsigned char *s, Py_ssize_t n)
{
    if (!s || n <= 0 || n > 8192)
        return NULL;
    return BN_bin2bn(s, (int)n, NULL);
}

/* Minimal big-endian encoding matching Python: to_bytes(...).lstrip(b'\0') or b'\0' */
static PyObject *
bn_to_min_bytes(const BIGNUM *x, int field_len)
{
    unsigned char *buf;
    int xlen, i, out_len;
    PyObject *result;

    xlen = BN_num_bytes(x);
    if (xlen <= 0) {
        const char zero = 0;
        return PyBytes_FromStringAndSize(&zero, 1);
    }
    if (field_len < xlen)
        field_len = xlen;
    buf = PyMem_Malloc((size_t)field_len);
    if (!buf)
        return PyErr_NoMemory();
    memset(buf, 0, (size_t)field_len);
    BN_bn2bin(x, buf + (field_len - xlen));

    out_len = field_len;
    i = 0;
    while (i < field_len - 1 && buf[i] == 0)
        i++;
    if (i > 0) {
        memmove(buf, buf + i, (size_t)(field_len - i));
        out_len = field_len - i;
    }
    result = PyBytes_FromStringAndSize((const char *)buf, out_len);
    PyMem_Free(buf);
    return result;
}

static PyObject *
py_dh_validate_public(PyObject *self, PyObject *args)
{
    const unsigned char *peer, *modp;
    Py_ssize_t peer_len, modp_len;
    BIGNUM *p = NULL, *y = NULL, *q = NULL, *one = NULL, *pm1 = NULL;
    BN_CTX *ctx = NULL;
    PyObject *result = NULL;
    int ok = 0;

    if (!PyArg_ParseTuple(args, "y#y#", &peer, &peer_len, &modp, &modp_len))
        return NULL;
    p = bn_from(modp, modp_len);
    y = bn_from(peer, peer_len);
    if (!p || !y) {
        PyErr_SetString(PyExc_ValueError, "bad DH integer");
        goto done;
    }
    ctx = BN_CTX_new();
    q = BN_new();
    one = BN_new();
    pm1 = BN_new();
    if (!ctx || !q || !one || !pm1) {
        PyErr_NoMemory();
        goto done;
    }
    BN_one(one);
    BN_sub(pm1, p, one); /* p-1 */

    /* 1 < y < p-1 */
    if (BN_cmp(y, one) <= 0 || BN_cmp(y, pm1) >= 0) {
        PyErr_SetString(PyExc_ValueError, "DH public value out of range");
        goto done;
    }
    /* safe-prime subgroup: y^q ≡ 1 (mod P), q = (P-1)/2 */
    BN_rshift1(q, pm1);
    if (BN_mod_exp(y, y, q, p, ctx) != 1) {
        PyErr_SetString(PyExc_RuntimeError, "DH modexp failed");
        goto done;
    }
    if (BN_is_one(y) != 1) {
        PyErr_SetString(PyExc_ValueError, "DH public value not in prime-order subgroup");
        goto done;
    }
    ok = 1;
    result = Py_True;
    Py_INCREF(result);

done:
    BN_free(p);
    BN_free(y);
    BN_free(q);
    BN_free(one);
    BN_free(pm1);
    BN_CTX_free(ctx);
    if (!ok && !PyErr_Occurred() && result == NULL)
        Py_RETURN_NONE;
    return result;
}

static PyObject *
py_dh_public(PyObject *self, PyObject *args)
{
    const unsigned char *priv, *modp;
    Py_ssize_t priv_len, modp_len;
    BIGNUM *p = NULL, *priv_bn = NULL, *g = NULL, *y = NULL;
    BN_CTX *ctx = NULL;
    PyObject *result = NULL;
    int field_len;

    if (!PyArg_ParseTuple(args, "y#y#", &priv, &priv_len, &modp, &modp_len))
        return NULL;
    p = bn_from(modp, modp_len);
    priv_bn = bn_from(priv, priv_len);
    if (!p || !priv_bn || BN_is_zero(priv_bn)) {
        Py_XDECREF(p);
        Py_XDECREF(priv_bn);
        return PyErr_Format(PyExc_ValueError, "bad DH private key");
    }
    g = BN_new();
    y = BN_new();
    ctx = BN_CTX_new();
    if (!g || !y || !ctx) {
        result = PyErr_NoMemory();
        goto done;
    }
    BN_set_word(g, 2);
    if (BN_mod_exp(y, g, priv_bn, p, ctx) != 1) {
        PyErr_SetString(PyExc_RuntimeError, "DH modexp failed");
        goto done;
    }
    field_len = (BN_num_bits(p) + 7) / 8;
    result = bn_to_min_bytes(y, field_len);

done:
    BN_free(p);
    BN_free(priv_bn);
    BN_free(g);
    BN_free(y);
    BN_CTX_free(ctx);
    return result;
}

static PyObject *
py_dh_shared(PyObject *self, PyObject *args)
{
    const unsigned char *priv, *peer, *modp;
    Py_ssize_t priv_len, peer_len, modp_len;
    BIGNUM *p = NULL, *priv_bn = NULL, *y = NULL, *s = NULL, *one = NULL, *pm1 = NULL;
    BN_CTX *ctx = NULL;
    PyObject *result = NULL;
    int field_len;

    if (!PyArg_ParseTuple(args, "y#y#y#", &priv, &priv_len, &peer, &peer_len, &modp, &modp_len))
        return NULL;
    p = bn_from(modp, modp_len);
    priv_bn = bn_from(priv, priv_len);
    y = bn_from(peer, peer_len);
    if (!p || !priv_bn || !y || BN_is_zero(priv_bn)) {
        PyErr_SetString(PyExc_ValueError, "bad DH values");
        goto done;
    }
    ctx = BN_CTX_new();
    s = BN_new();
    one = BN_new();
    pm1 = BN_new();
    if (!ctx || !s || !one || !pm1) {
        result = PyErr_NoMemory();
        goto done;
    }
    BN_one(one);
    BN_sub(pm1, p, one);
    if (BN_cmp(y, one) <= 0 || BN_cmp(y, pm1) >= 0) {
        PyErr_SetString(PyExc_ValueError, "DH public value out of range");
        goto done;
    }
    if (BN_mod_exp(s, y, priv_bn, p, ctx) != 1) {
        PyErr_SetString(PyExc_RuntimeError, "DH modexp failed");
        goto done;
    }
    field_len = (BN_num_bits(p) + 7) / 8;
    result = bn_to_min_bytes(s, field_len);

done:
    BN_free(p);
    BN_free(priv_bn);
    BN_free(y);
    BN_free(s);
    BN_free(one);
    BN_free(pm1);
    BN_CTX_free(ctx);
    return result;
}

/* ------------------------------------------------------------------ */

static PyMethodDef NativeMethods[] = {
    {"aead_encrypt", py_aead_encrypt, METH_VARARGS,
     "aead_encrypt(enc_key: bytes, mac_key: bytes, plaintext: bytes) -> bytes\n"
     "AES-256-CBC + HMAC-SHA256 Encrypt-then-MAC. Returns iv||ct||mac."},
    {"aead_decrypt", py_aead_decrypt, METH_VARARGS,
     "aead_decrypt(enc_key: bytes, mac_key: bytes, data: bytes) -> bytes\n"
     "Verify HMAC then decrypt. Raises ValueError on failure."},
    {"filter_telnet", filter_telnet, METH_VARARGS,
     "filter_telnet(data: bytes) -> (payload: bytes, replies: bytes)"},
    {"squeeze_backspace", squeeze_backspace, METH_VARARGS,
     "squeeze_backspace(data: bytes) -> bytes"},
    {"pbkdf2_sha256", pbkdf2_sha256, METH_VARARGS,
     "pbkdf2_sha256(password: bytes, salt: bytes, iterations: int) -> bytes"},
    {"sha256", py_sha256, METH_VARARGS,
     "sha256(data: bytes) -> bytes"},
    {"hmac_sha256", py_hmac_sha256, METH_VARARGS,
     "hmac_sha256(key: bytes, data: bytes) -> bytes"},
    {"derive_session_keys", py_derive_session_keys, METH_VARARGS,
     "derive_session_keys(shared: bytes) -> (enc_key: bytes, mac_key: bytes)"},
    {"dh_validate_public", py_dh_validate_public, METH_VARARGS,
     "dh_validate_public(peer: bytes, modp: bytes) -> None\n"
     "Raises ValueError if outside the prime-order subgroup."},
    {"dh_public", py_dh_public, METH_VARARGS,
     "dh_public(priv: bytes, modp: bytes) -> bytes"},
    {"dh_shared", py_dh_shared, METH_VARARGS,
     "dh_shared(priv: bytes, peer: bytes, modp: bytes) -> bytes"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef native_module = {
    PyModuleDef_HEAD_INIT,
    "dmcd.native.dmcd_native",
    "LibreDM native crypto (AES-ETM, PBKDF2, DH, HMAC) + telnet filter.",
    -1,
    NativeMethods
};

PyMODINIT_FUNC
PyInit_dmcd_native(void)
{
    return PyModule_Create(&native_module);
}
