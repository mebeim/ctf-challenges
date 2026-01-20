#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "commands.h"
#include "telemetry.h"
#include "util.h"

typedef struct __attribute__((packed)) {
    // Same names used in D-Orbit CSV parser for simplicity
    double timestamp;
    double gps_pos[3];
    double gps_vel[3];
    float pstnOdsECIF[3];
    float vlctyOdsECIF[3];
    float orbit[6];
    float quaternion[4];
    float omega[3];
} telemetry_row;

static_assert(sizeof(telemetry_row) == 132, "telemetry_row size is not correct");

static void *telemetry_data;
static uint32_t last_row_index;

void telemetry_reset(void) {
    fputs("base station requested system reset\n", stderr);
    // This leaks memory but allows multiple mmaps in case it is needed for... reasons
    telemetry_data = NULL;
    last_row_index = -1U;
}

void handle_telemetry(int cmd, uint32_t row_index) {
    const size_t row_offset = row_index * sizeof(telemetry_row);
    size_t telemetry_map_size = PAGE_SIZE;

    // [Re]map telemetry file if needed
    if (!telemetry_data || last_row_index != row_index) {
        const char *telemetry_file_path = getenv("TELEMETRY_FILE_PATH") ?: "/input/telemetry";

        struct stat st;
        if (stat(telemetry_file_path, &st) == -1) {
            perror_stdout("stat failed");
            return;
        }

        const size_t telemetry_file_size = st.st_size;
        if (row_offset + sizeof(telemetry_row) > telemetry_file_size) {
            puts("not enough telemetry data");
            return;
        }

        if (telemetry_file_size > telemetry_map_size)
            telemetry_map_size *= 2;

        if (telemetry_data)
            if (munmap(telemetry_data, telemetry_map_size) == -1) {
                // Error unmapping previous data: warn and do nothing
                perror_stdout("munmap failed");
                return;
            }

        // Always need to map at least 2 pages since one page is not multiple of
        // sizeof(telemetry_row)
        const size_t file_offset = (row_offset / PAGE_SIZE) * PAGE_SIZE;
        telemetry_data = map_file(telemetry_file_path, telemetry_map_size, file_offset);
        if (!telemetry_data) {
            // Error mapping file: do nothing
            return;
        }

        last_row_index = row_index;
    }

    const size_t row_page_offset = row_offset % PAGE_SIZE;
    const telemetry_row *row = (telemetry_row *)((unsigned char *)telemetry_data + row_page_offset);
    char human_time[0x20];

    switch (cmd) {
    case CMD_TELEMETRY_TIMESTAMP:
        timestamp_to_iso_str(row->timestamp, human_time, sizeof(human_time));
        printf("time %s\n", human_time);
        break;

    case CMD_TELEMETRY_GPS:
        printf("gps pos=%f,%f,%f vel=%f,%f,%f\n",
            row->gps_pos[0], row->gps_pos[1], row->gps_pos[2],
            row->gps_vel[0], row->gps_vel[1], row->gps_vel[2]);
        break;

    case CMD_TELEMETRY_ECIF:
        printf("ecif pos=%f,%f,%f vel=%f,%f,%f\n",
            row->pstnOdsECIF[0], row->pstnOdsECIF[1], row->pstnOdsECIF[2],
            row->vlctyOdsECIF[0], row->vlctyOdsECIF[1], row->vlctyOdsECIF[2]);
        break;

    case CMD_TELEMETRY_ORBIT:
        printf("orbit=%f,%f,%f,%f,%f,%f\n",
            row->orbit[0], row->orbit[1], row->orbit[2],
            row->orbit[3], row->orbit[4], row->orbit[5]);
        break;

    case CMD_TELEMETRY_ORIENTATION:
        printf("orientation=%f,%f,%f,%f\n",
            row->quaternion[0], row->quaternion[1], row->quaternion[2],
            row->quaternion[3]);
        break;

    case CMD_TELEMETRY_OMEGA:
        printf("omega=%f,%f,%f\n",
            row->quaternion[0], row->quaternion[1], row->quaternion[2]);
        break;

    default:
        // We should never get here if the caller is sane
        puts("internal error");
        break;
    }
}
