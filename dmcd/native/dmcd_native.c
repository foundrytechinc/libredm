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
#include <string.h>

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
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef native_module = {
    PyModuleDef_HEAD_INIT,
    "dmcd.native.dmcd_native",
    "LibreDM native hot paths (AES-ETM, telnet filter, PBKDF2).",
    -1,
    NativeMethods
};

PyMODINIT_FUNC
PyInit_dmcd_native(void)
{
    return PyModule_Create(&native_module);
}
