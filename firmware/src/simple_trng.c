#include "simple_trng.h"
#include "host_messaging.h"
#include "ti/driverlib/dl_trng.h"

#define TRNG_CMD_TIMEOUT 100000UL

static volatile bool trng_ready = false;

static bool wait_cmd_done(void) {
    uint32_t timeout = TRNG_CMD_TIMEOUT;
    while (!DL_TRNG_isCommandDone(TRNG)) {
        if (--timeout == 0) {
            return false;
        }
    }
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);
    return true;
}

bool trng_init(void) {
    uint8_t results;
    trng_ready = false;

    wait_cmd_done();

    /* Digital startup self-test */
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_TEST_DIG);
    if (!wait_cmd_done()) {
        print_debug("trng dig timeout");
        trng_shutdown();
        return false;
    }

    results = DL_TRNG_getDigitalHealthTestResults(TRNG);
    if (results != DL_TRNG_DIGITAL_HEALTH_TEST_SUCCESS) {
        print_hex_debug(&results, sizeof(results));
        print_debug("trng dig fail");
        trng_shutdown();
        return false;
    }

    /* Analog startup self-test */
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_TEST_ANA);
    if (!wait_cmd_done()) {
        print_debug("trng ana timeout");
        trng_shutdown();
        return false;
    }

    results = DL_TRNG_getAnalogHealthTestResults(TRNG);
    if (results != DL_TRNG_ANALOG_HEALTH_TEST_SUCCESS) {
        print_debug("trng ana fail");
        trng_shutdown();
        return false;
    }

    /* Clear stale capture-ready event from self-tests */
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);

    /* Re-enter normal functional mode with configured decimation */
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);
    if (!wait_cmd_done()) {
        trng_shutdown();
        return false;
    }

    DL_TRNG_setDecimationRate(TRNG, DL_TRNG_DECIMATION_RATE_8);


    /* Discard current random */
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);

    trng_ready = true;
    return true;
}

uint32_t trng_get_u32(void) {
    if (!trng_ready) {
        return 0;
    }

    /* If hardware detected low entropy, fail closed */
    if (DL_TRNG_isHealthTestFail(TRNG)) {
        trng_shutdown();
        return 0;
    }

    /* Wait for fresh entropy */
    while (!DL_TRNG_isCaptureReady(TRNG)) {
        if (DL_TRNG_isHealthTestFail(TRNG)) {
            trng_shutdown();
            return 0;
        }
    }

    uint32_t out = DL_TRNG_getCapture(TRNG);
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);

    return out;
}

void trng_shutdown(void) {
    trng_ready = false;
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_PWROFF);
    wait_cmd_done();
}
