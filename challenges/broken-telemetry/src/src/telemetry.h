#ifndef TELEMETRY_H
#define TELEMETRY_H

#include <stdint.h>

void handle_telemetry(int cmd, uint32_t row_index);
void telemetry_reset(void);

#endif // TELEMETRY_H
