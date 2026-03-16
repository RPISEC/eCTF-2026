/*
* hardware_crypto.c
* Implements WolfCrypt callback to use AESADV hardware AES engine for AES-GCM operations.
* User must specify HARDWARE_CRYPTO_DEVICE_ID as devId in wolfcrypt init function to use this callback.
* Besides that, all usage is seamless and handled by wolfcrypt.
* Usage:
    wc_AesInit(&aes, NULL, HARDWARE_CRYPTO_DEVICE_ID); // important: set devId to HARDWARE_CRYPTO_DEVICE_ID defined in hardware_crypto.h
    wc_AesGcmSetKey(&aes, YOUR_KEY, sizeof(YOUR_KEY));
    ret = wc_AesGcmEncrypt(
        &aes,
        ciphertext,                     // out
        TEST_PLAINTEXT, TEST_PT_SZ,     // in, sz
        TEST_IV,        sizeof(TEST_IV),// iv, ivSz
        auth_tag,       AUTH_TAG_SZ,    // tag, tagSz
        TEST_AAD,       TEST_AAD_SZ     // aad, aadSz
    );
    if (ret != 0) {
        print_debug("Encrypt failed\n");
    }

* For more examples see: aes_test.c
*/

// config for hardware interface
#include <ti/devices/msp/msp.h>
#include <ti/driverlib/driverlib.h>
#include <ti/driverlib/m0p/dl_core.h>

// wolfcrypt library includes
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "hardware_crypto.h"

#define DIR_ENCRYPT 1  // wolfcrypt cipher.enc boolean

// this is defined in ti_msp_dl_config.c, but as static const; so we use our own config here
static DL_AESADV_Config _hc_AESADV_config = {
    .mode = DL_AESADV_MODE_GCM_AUTONOMOUS,            // changed from the above for simplicity
    .direction = DL_AESADV_DIR_ENCRYPT,               // encrypt/decrypt direction
    .ctr_ctrWidth = DL_AESADV_CTR_WIDTH_32_BIT,       // counter width
    .cfb_fbWidth = DL_AESADV_FB_WIDTH_128,            // cipher feedback width (ignored for GCM)
    .ccm_ctrWidth = DL_AESADV_CCM_CTR_WIDTH_2_BYTES,  // CCM counter width (ignored for GCM)
    .ccm_tagWidth = DL_AESADV_CCM_TAG_WIDTH_1_BYTE,   // CCM tag width (ignored for GCM)
    .iv = NULL,                                       // IV
    .nonce = NULL,                                    // nonce
    .lowerCryptoLength = 0,                           // lower 32 bits of the length of the content data  (61 bits for full number)
    .upperCryptoLength = 0,                           // upper 29 bits of the length of the content data
    .aadLength = 0,                                   // length of Additional Authentication Data (AAD)
};

typedef struct {
    uint32_t * arr;
    uint32_t length;
} Buffer_uint32;

// state flags for AES engine
static volatile uint32_t _hc_operation_in_progress = false;
static volatile uint32_t _hc_aad_flag = 0;

// global state for interrupt handler
static Buffer_uint32 _hc_aes_aad_input = {NULL, 0};
static Buffer_uint32 _hc_aes_input = {NULL, 0};
static Buffer_uint32 _hc_aes_output = {NULL, 0};
static uint32_t _hc_aes_tag[AES_AUTH_TAG_SIZE/sizeof(uint32_t)];
static volatile uint32_t _hc_input_idx = 0;
static volatile uint32_t _hc_output_idx = 0;

/**
 * Note: wolfcrypt uses very similar struct definitions for wc_CryptoCb_AesAuthEnc and wc_CryptoCb_AesAuthDec
 * from wolfssl/wolfcrypt/cryptocb.h
 * with the only difference being that tag is const in decryption.
 * We'll "cast" both to the following struct definition which has every field we need.
 * This type uses type definitions which match wolfcrypt's.
 */
typedef struct {
    const uint8_t* in;
    uint8_t*       out;
    word32         sz;
    const uint8_t* iv;
    word32         ivSz;
    const uint8_t* authIn;
    word32         authInSz;
    uint8_t*       authTag;
    word32         authTagSz;
    int            enc;          /* DIR_ENCRYPT or DIR_DECRYPT */
} HC_AesGcmParams;

static int extract_aesgcm_params(const wc_CryptoInfo* info, HC_AesGcmParams* p)
{
    p->enc = info->cipher.enc;

    if (info->cipher.enc == DIR_ENCRYPT) {
        const wc_CryptoCb_AesAuthEnc* e = &info->cipher.aesgcm_enc;
        p->in        = e->in;
        p->out       = e->out;
        p->sz        = e->sz;
        p->iv        = e->iv;
        p->ivSz      = e->ivSz;
        p->authIn    = e->authIn;
        p->authInSz  = e->authInSz;
        p->authTag   = e->authTag;
        p->authTagSz = e->authTagSz;
    } else {
        const wc_CryptoCb_AesAuthDec* d = &info->cipher.aesgcm_dec;
        p->in        = d->in;
        p->out       = d->out;
        p->sz        = d->sz;
        p->iv        = d->iv;
        p->ivSz      = d->ivSz;
        p->authIn    = d->authIn;
        p->authInSz  = d->authInSz;
        p->authTag   = (uint8_t*)d->authTag;  /* cast away const: we only read it on decrypt */
        p->authTagSz = d->authTagSz;
    }
    return 0;
}


bool init_hardware_crypto(void) {
    // Register the hardware crypto callback with wolfcrypt
    int ret = wc_CryptoCb_RegisterDevice(
        HARDWARE_CRYPTO_DEVICE_ID, callbackHardwareCrypto, NULL
    );
    if (ret != 0) {
        return false;
    }

    // Enables a AES_ADV interrupt in the NVIC interrupt controller
    NVIC_EnableIRQ(AESADV_INT_IRQn);
    DL_SYSCTL_disableSleepOnExit();

    return true;
}


/**
 * For AES GCM encrypt/decrypt: Setup config and flags for AES engine, block until operation is complete, and return result.
 * For all other operations: return CRYPTOCB_UNAVAILABLE to fall back to wolfcrypt software implementation.
 */
int callbackHardwareCrypto(int devId, wc_CryptoInfo* info, void* ctx) {

    // Return CRYPTOCB_UNAVAILABLE to fall back to software implementation for different algorithms
    if (info->algo_type != WC_ALGO_TYPE_CIPHER || info->cipher.type != WC_CIPHER_AES_GCM) {
        return CRYPTOCB_UNAVAILABLE;
    }

    Aes* aes;
    HC_AesGcmParams params;
    extract_aesgcm_params(info, &params);
    int direction;

    // reset flags
    _hc_input_idx = 0;
    _hc_output_idx = 0;
    _hc_aad_flag = 0;

    if (info->cipher.enc == DIR_ENCRYPT) {
        aes = info->cipher.aesgcm_enc.aes;
        direction = DL_AESADV_DIR_ENCRYPT;
    } else {
        aes = info->cipher.aesgcm_dec.aes;
        direction = DL_AESADV_DIR_DECRYPT;
    }

    // make sure we are using the right key size
    // support only 32 byte keys to avoid mistakingly using a smaller key
    if (aes->keylen != 32) {
        return BAD_FUNC_ARG;
    }

    // load key into AES engine
    DL_AESADV_setKeySize(AESADV, DL_AESADV_KEY_SIZE_256_BIT);
    DL_AESADV_setKeyAligned(AESADV, aes->key, DL_AESADV_KEY_SIZE_256_BIT);

    // set config before initializing AES engine
    _hc_AESADV_config.direction = direction;
    _hc_AESADV_config.iv = (uint8_t *)params.iv;
    _hc_AESADV_config.nonce = NULL;
    _hc_AESADV_config.lowerCryptoLength = params.sz & 0xFFFFFFFF;
    _hc_AESADV_config.upperCryptoLength = 0; // not supporting content sizes of more than 4GB for simplicity
    _hc_AESADV_config.aadLength = params.authInSz;

    // write the AES context configuration
    DL_AESADV_initGCM(AESADV, (DL_AESADV_Config *) &_hc_AESADV_config);


    /* set global state for interrupt handler
       Note: we cannot use the same buffers as wolfcrypt uses
       since they are not guaranteed to by 4-byte aligned, which is required for the AES data load operations
       so we allocate our own uint32_t buffers and copy data over to them
       we use length to refer to number of items, not size in bytes, so length is rounded up from size to ensure we have enough space for the data
    */
    _hc_aes_aad_input.length =
        ((params.authInSz + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) *
        (AES_BLOCK_SIZE / sizeof(uint32_t));
    _hc_aes_aad_input.arr = malloc(_hc_aes_aad_input.length * sizeof(uint32_t));

    _hc_aes_input.length = ((params.sz + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) *
                           (AES_BLOCK_SIZE / sizeof(uint32_t));
    _hc_aes_input.arr = malloc(_hc_aes_input.length * sizeof(uint32_t));

    _hc_aes_output.length = _hc_aes_input.length;
    _hc_aes_output.arr = malloc(_hc_aes_output.length * sizeof(uint32_t));

    XMEMSET(_hc_aes_aad_input.arr, 0, _hc_aes_aad_input.length * sizeof(uint32_t));
    XMEMSET(_hc_aes_input.arr, 0, _hc_aes_input.length * sizeof(uint32_t));
    XMEMSET(_hc_aes_output.arr, 0, _hc_aes_output.length * sizeof(uint32_t));

    XMEMCPY(_hc_aes_aad_input.arr, params.authIn, params.authInSz);
    XMEMCPY(_hc_aes_input.arr, params.in, params.sz);

    // load aad
    _hc_aad_flag = 1;

    DL_AESADV_clearInterruptStatus(AESADV, DL_AESADV_INTERRUPT_INPUT_READY);
    DL_AESADV_enableInterrupt(AESADV, DL_AESADV_INTERRUPT_INPUT_READY);
    while(_hc_input_idx < _hc_aes_aad_input.length){
        __WFE();
    }

    // reset flags
    _hc_input_idx = 0;
    _hc_output_idx = 0;
    _hc_aad_flag = 0;

    // load input data and enable each of the interrupts that can happen during the encryption/decryption operation
    _hc_operation_in_progress = true;

    DL_AESADV_clearInterruptStatus(AESADV,DL_AESADV_INTERRUPT_OUTPUT_READY);
    DL_AESADV_enableInterrupt(AESADV,DL_AESADV_INTERRUPT_OUTPUT_READY);
    DL_AESADV_clearInterruptStatus(AESADV, DL_AESADV_INTERRUPT_INPUT_READY);
    DL_AESADV_enableInterrupt(AESADV, DL_AESADV_INTERRUPT_INPUT_READY);
    DL_AESADV_clearInterruptStatus(AESADV,DL_AESADV_INTERRUPT_SAVED_OUTPUT_CONTEXT_READY);
    DL_AESADV_enableInterrupt(AESADV,DL_AESADV_INTERRUPT_SAVED_OUTPUT_CONTEXT_READY);

    while(_hc_operation_in_progress){
        __WFE();
    }

    // copy results back to wolfcrypt
    XMEMCPY(params.out, _hc_aes_output.arr, params.sz);

    // cleanup (zero out buffers as they may contain sensitive data)
    XMEMSET(_hc_aes_aad_input.arr, 0, _hc_aes_aad_input.length * sizeof(uint32_t));
    XMEMSET(_hc_aes_input.arr, 0, _hc_aes_input.length * sizeof(uint32_t));
    XMEMSET(_hc_aes_output.arr, 0, _hc_aes_output.length * sizeof(uint32_t));
    free((void*)_hc_aes_aad_input.arr);
    free((void*)_hc_aes_input.arr);
    free((void*)_hc_aes_output.arr);

    if (info->cipher.enc == DIR_ENCRYPT) {
        // for encryption, copy the computed tag out to wolfcrypt
        XMEMCPY(params.authTag, (void*)_hc_aes_tag, params.authTagSz);
    } else {
        /* for decryption, compare the hardware-computed tag against
           the expected tag passed in by the caller.
           If they don't match, the data was tampered with or the
           wrong key/IV/AAD was used. Zero the output to prevent the
           caller from using unauthenticated plaintext, then fail. */
        if (XMEMCMP(params.authTag, (void*)_hc_aes_tag, params.authTagSz) != 0) {
            XMEMSET(params.out, 0, params.sz);
            return AES_GCM_AUTH_E;
        }
    }

    // success
    return 0;
}

/**
 * AESADV_IRQHandler is mostly taken from the example code provided by TI
 * This handles interrupts from the AES engine
 * using the global variable flags and indices to manage state.
 * The name of this handler is important as it is referenced in the startup file.
 */
void AESADV_IRQHandler(void)
{
    switch(DL_AESADV_getPendingInterrupt(AESADV)){
        case DL_AESADV_IIDX_INPUT_READY:
            if(_hc_aad_flag == 1){
                // load aad (additional authentication data) into engine
                DL_AESADV_loadInputDataAligned(AESADV, &_hc_aes_aad_input.arr[_hc_input_idx]);
                _hc_input_idx = _hc_input_idx + 4;
                if(_hc_input_idx >= _hc_aes_aad_input.length){
                    DL_AESADV_disableInterrupt(AESADV, DL_AESADV_INTERRUPT_INPUT_READY);
                }
            }
            else {
                // Load input plaintext/ciphertext into engine
                DL_AESADV_loadInputDataAligned(AESADV, &_hc_aes_input.arr[_hc_input_idx]);
                // increment input index for next block of input
                _hc_input_idx = _hc_input_idx + 4;
                if(_hc_input_idx >= _hc_aes_input.length){
                    DL_AESADV_disableInterrupt(AESADV, DL_AESADV_INTERRUPT_INPUT_READY);
                }
            }
            break;

        case DL_AESADV_IIDX_OUTPUT_READY:
            DL_AESADV_readOutputDataAligned(AESADV, &_hc_aes_output.arr[_hc_output_idx]);
            // increment output index for next block of output
            _hc_output_idx = _hc_output_idx + 4;
            DL_AESADV_clearInterruptStatus(AESADV, DL_AESADV_INTERRUPT_OUTPUT_READY);
            if(_hc_output_idx >= _hc_aes_output.length){
                DL_AESADV_disableInterrupt(AESADV, DL_AESADV_INTERRUPT_OUTPUT_READY);
            }
            break;

        case DL_AESADV_IIDX_SAVED_OUTPUT_CONTEXT_READY:
            // read output tag
            DL_AESADV_readTAGAligned(AESADV, _hc_aes_tag);
            DL_AESADV_disableInterrupt(AESADV, DL_AESADV_INTERRUPT_SAVED_OUTPUT_CONTEXT_READY);
            // notify that operation is complete; once writing has finished
            _hc_operation_in_progress = false;
            break;
        default :
            break;

    }
}
