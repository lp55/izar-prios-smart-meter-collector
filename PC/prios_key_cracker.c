//
// Take a bunch of PRIOS WMBus frames, and find a decryption key that allows decoding all of them.
// Unpolished code: do not use in production.
//

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <omp.h>

// Use the PRIOS functions from the ST code.
#include <PRIOS.h>
#include "config.h"

// Declare those since they're not exported by the ST code.
uint32_t read_uint32_le(uint8_t *data, int offset);
uint32_t read_uint32_be(uint8_t *data, int offset);
uint32_t preparePRIOSKey(uint8_t *bytes);

// Try to decode a payload with a key:
uint8_t try_key(uint8_t *key_bytes, uint8_t *frame, uint8_t *out) {
    uint32_t prepared_key = preparePRIOSKey(key_bytes);
    return decodePRIOSPayload(frame, 11, prepared_key, out);
}

// Check that a decoded payload is coherent with the data we expect:
uint8_t check_decoded_payload(uint8_t *decoded_frame, uint32_t *total_consumption, uint32_t *last_month_total_consumption, uint8_t *year, uint8_t *month, uint8_t *day) {
    // Check that the consumptions look correct:
    *total_consumption = read_uint32_le(decoded_frame, 1);
    *last_month_total_consumption = read_uint32_le(decoded_frame, 5);
    if (*last_month_total_consumption > *total_consumption) {
        return 0;
    }
#ifdef CONSUMPTION_RANGE_MIN
    if (*total_consumption < CONSUMPTION_RANGE_MIN) {
        return 0;
    }
    if (*last_month_total_consumption < CONSUMPTION_RANGE_MIN) {
        return 0;
    }
#endif
#ifdef CONSUMPTION_RANGE_MAX
    if (*total_consumption > CONSUMPTION_RANGE_MAX) {
        return 0;
    }
    if (*last_month_total_consumption > CONSUMPTION_RANGE_MAX) {
        return 0;
    }
#endif

    // Check that the date is correct:
    *year = ((decoded_frame[10] & 0xF0) >> 1) + ((decoded_frame[9] & 0xE0) >> 5);
    *month = decoded_frame[10] & 0xF;
    *day = decoded_frame[9] & 0x1F;
    if (*year > 99 || *month > 12 || *day > 31) {
        return 0;
    }
#ifdef TEST_YEAR
    if (*year != TEST_YEAR) {
        return 0;
    }
#endif
#ifdef TEST_MONTH
    if (*month != TEST_MONTH) {
        return 0;
    }
#endif
#ifdef TEST_DAY
    if (*day != TEST_DAY) {
        return 0;
    }
#endif

    return 1;
}

int main(int argc, char **argv) {
	uint32_t total_consumption; uint32_t last_month_total_consumption; uint8_t year; uint8_t month; uint8_t day;
    uint8_t found_keys = 0;

    uint32_t local_count = 0u;
    const uint64_t step_size = 300000000ul;
    uint64_t steps_done = 0ul;
    
    setbuf(stdout, NULL);

    for (uint8_t j=0, count=sizeof(frames) / sizeof(frames[0]); j<count; j++) {
        for (uint8_t i=0; i<sizeof(frames[0]); i++) {
            printf("%x", frames[j][i]);
        }
        printf("\n");
    }
 
    //swaps id and version (needed for arrow meters - https://github.com/wmbusmeters/wmbusmeters/issues/1416)
    if (argc > 1) {
        uint8_t block1[2];
        for (uint8_t j=0, count=sizeof(frames) / sizeof(frames[0]); j<count; j++) {
//Original:   19442434 8207 6261 9119 A2ED0E0013C5F135F91623B9CBC28C6A
//Modificado: 19442434 6261 9119 8207 a2ed0e0013c5f135f91623B9cBc28c6a
            memcpy(block1, &frames[j][4], 2);
            memcpy(&frames[j][4], &frames[j][6], 2);
            memcpy(&frames[j][6], &frames[j][8], 2);
            memcpy(&frames[j][8], block1, 2);           
        }
        printf("Frames swapped\n");
        for (uint8_t j=0, count=sizeof(frames) / sizeof(frames[0]); j<count; j++) {
            for (uint8_t i=0; i<sizeof(frames[0]); i++) {
                printf("%x", frames[j][i]);
            }
            printf("\n");
        }
    }
    
    
    // Loop over all the possible keys:
    #pragma omp parallel for firstprivate(local_count)
    for (uint32_t z=0; z<UINT32_MAX; z++) {
        uint64_t i = (uint64_t) 0xF8836DE6 << 32 | z;
        uint8_t decoded_frame[11];
        uint8_t success = 1;
        // Test all frames in sequence until one fails:
        for (uint8_t j=0, count=sizeof(frames) / sizeof(frames[0]); j<count; j++) {
	        // Check if the payload can be decoded:
	        if (!try_key((uint8_t *) &i, frames[j], decoded_frame)) {
	        	success = 0;
	            break;
	        }

	        // Check the decoded payload for consistency:
	        if (!check_decoded_payload(decoded_frame, &total_consumption, &last_month_total_consumption, &year, &month, &day)) {
	        	success = 0;
	            break;
	        }
        }

        if (success) {
	        printf(
	        	"Candidate key: %.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x (wmbusmeters format) %.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x0000000000000000 (esphome format): First frame: current: %d, H0: %d H0 date: %.2d-%.2d-%.2d\n",
	        	(uint8_t)(i & 0xFF), (uint8_t)((i >> 8) & 0xFF), (uint8_t)((i >> 16) & 0xFF), (uint8_t)((i >> 24) & 0xFF), (uint8_t)((i >> 32) & 0xFF), (uint8_t)((i >> 40) & 0xFF), (uint8_t)((i >> 48) & 0xFF), (uint8_t)((i >> 56) & 0xFF),
	        	(uint8_t)(i & 0xFF), (uint8_t)((i >> 8) & 0xFF), (uint8_t)((i >> 16) & 0xFF), (uint8_t)((i >> 24) & 0xFF), (uint8_t)((i >> 32) & 0xFF), (uint8_t)((i >> 40) & 0xFF), (uint8_t)((i >> 48) & 0xFF), (uint8_t)((i >> 56) & 0xFF),
	        	total_consumption, last_month_total_consumption, year, month, day
	        );
            
            #pragma omp atomic
	        ++found_keys;
        }

        if (++local_count % step_size == 0) {
            #pragma omp atomic
            steps_done += step_size;
            time_t now;
            
            time(&now);
            struct tm *local = localtime(&now);
            int dt_hours = local->tm_hour;
            int dt_minutes = local->tm_min;
            int dt_seconds = local->tm_sec;
            int dt_day = local->tm_mday;
            int dt_month = local->tm_mon + 1;
            int dt_year = local->tm_year + 1900;
            
            printf("[%d] [%d-%d-%d %d:%d:%d] Tried %ld keys (%.2f%%) [Processed from 0x%.8x to 0x%.8x]\n", 
                omp_get_thread_num(), 
                dt_year, dt_month, dt_day, dt_hours, dt_minutes, dt_seconds, 
                steps_done, 
                steps_done / (float)UINT32_MAX * 100.0f, 
                z - local_count + 1, z);
        }
    }

    printf("found_keys: %d\n", found_keys);

    return found_keys > 0;
}
