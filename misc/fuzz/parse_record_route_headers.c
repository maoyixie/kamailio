#include "../config.h"
#include "../parser/sdp/sdp.h"
#include "../parser/parse_uri.c"
#include "../parser/parse_hname2.h"
#include "../parser/contact/parse_contact.h"
#include "../parser/parse_from.h"
#include "../parser/parse_to.h"
#include "../parser/parse_rr.h"
#include "../parser/parse_refer_to.h"
#include "../parser/parse_ppi_pai.h"
#include "../parser/parse_privacy.h"
#include "../parser/parse_diversion.h"
#include "../parser/parse_identityinfo.h"
#include "../parser/parse_disposition.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	// Create a buffer to hold the data
	char *buf = (char *)malloc(Size + 1);
	if(!buf) {
		return 0;
	}

	// Copy the data into the buffer and null-terminate it
	memcpy(buf, Data, Size);
	buf[Size] = '\0';

	// Create a sip_msg_t struct
	sip_msg_t msg;

	// Set the msg.buf and msg.len fields
	msg.buf = buf;
	msg.len = Size;

	// Call the function to be fuzzed
	parse_record_route_headers(&msg);

	// Free the allocated memory
	free(buf);

	// Indicate that the fuzzing was successful
	return 0;
}