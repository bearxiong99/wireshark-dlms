/*
 * obis.h - OBIS (OBject Identification System) code names
 */

static const val64_string obis_code_names[] = {

    /* Application-independent OBIS codes and names */
    { 0x0000280000ff, "Current association" },
    { 0x0000290000ff, "SAP assignment" },
    { 0x00002a0000ff, "COSEM logical device name" },

    /* Add your application-specific OBIS codes and names here */


    /* Terminating entry (do not delete) */
    { 0, 0 }
};
