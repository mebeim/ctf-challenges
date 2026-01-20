#ifndef COMMANDS_H
#define COMMANDS_H

/* Note: first cmd needs to be 0x00 for input parsing purposes */
#define CMD_TELEMETRY_TIMESTAMP   0x00 // Time
#define CMD_TELEMETRY_GPS         0x01 // GPS pos (3d) + vel (3d)
#define CMD_TELEMETRY_ECIF        0x02 // Earth-centered inertial pos (3d) + vel (3d)
#define CMD_TELEMETRY_ORBIT       0x03 // Orbit pos (3d) + vel (3d)
#define CMD_TELEMETRY_ORIENTATION 0x04 // Orientation vector (4d)
#define CMD_TELEMETRY_OMEGA       0x05 // Angular velocity (3d)
#define CMD_TELEMETRY_MAX         CMD_TELEMETRY_OMEGA

#define CMD_PATCH                 0xfe
#define CMD_RESET                 0xff

#endif // COMMANDS_H
