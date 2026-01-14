/**
 * @file status_led.h
 * @author Samuel Meyers
 * @brief eCTF Status LED Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef __STATUS_LED__
#define __STATUS_LED__

#include "ti_msp_dl_config.h"

#define STATUS_LED_ON(void) DL_GPIO_setPins(LEDS_PORT, LEDS_STATUS_LED_PIN)
#define STATUS_LED_OFF(void) DL_GPIO_clearPins(LEDS_PORT, LEDS_STATUS_LED_PIN)

#endif // __STATUS_LED__
