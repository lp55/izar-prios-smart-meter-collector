//
// Take a bunch of PRIOS WMBus frames, and find a decryption key that allows decoding all of them.
// Unpolished code: do not use in production.
//

#include <stdio.h>
#include <stdint.h>
#include <time.h>
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
    uint8_t decoded_frame[11];

    uint64_t local_count = 0ul;
    uint64_t step_size = 1000000000ul;
    uint64_t steps_done = 0ul;
    uint64_t skip = 0ul;
    
    setbuf(stdout, NULL);
    
    //skips x initial tries (valued passed in hex)
    if (argc > 1)
    {
        //sscanf(argv[1], "%I64x", &skip);
        sscanf(argv[1], "%lx", &skip);
        printf("Skipping first %.16lx possible keys\n", skip);
        steps_done += skip;
    }
    
    
    // Loop over all the possible keys:
    #pragma omp parallel for firstprivate(local_count)
    //for (uint64_t i=skip; i<0xffffffffffffffff; i++) {
        for (uint64_t i=skip; i<UINT64_MAX; i++) {
        // Test all frames in sequence until one fails:
        uint8_t success = 1;
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
	        	"Candidate key: {0x%.2x, 0x%.2x, 0x%.2x, 0x%.2x, 0x%.2x, 0x%.2x, 0x%.2x, 0x%.2x}: First frame: current: %d, H0: %d H0 date: %.2d-%.2d-%.2d\n",
	        	(uint8_t)(i & 0xFF), (uint8_t)((i >> 8) & 0xFF), (uint8_t)((i >> 16) & 0xFF), (uint8_t)((i >> 24) & 0xFF), (uint8_t)((i >> 32) & 0xFF), (uint8_t)((i >> 40) & 0xFF), (uint8_t)((i >> 48) & 0xFF), (uint8_t)((i >> 56) & 0xFF),
	        	total_consumption, last_month_total_consumption, year, month, day
	        );
	        found_keys++;
        }

        if (++local_count % step_size == 0)
        {
            #pragma omp atomic
            steps_done += step_size;
            time_t now;
            
            time(&now);
            struct tm *local = localtime(&now);
            int hours = local->tm_hour;
            int minutes = local->tm_min;
            int seconds = local->tm_sec;
            int day = local->tm_mday;
            int month = local->tm_mon + 1;
            int year = local->tm_year + 1900;
            
            //printf("[%d] local_count %.16ld\n", omp_get_thread_num(), local_count);
            printf("[%d] [%d-%d-%d %d:%d:%d] Tried %ld keys (%.2f%%) [Processed from %.16lx to %.16lx]\n", 
                omp_get_thread_num(), 
                year, month, day, hours, minutes, seconds, 
                steps_done, 
                steps_done / UINT64_MAX * 100.0, 
                i - local_count, i);
        }

    }

    return found_keys > 0;
}
