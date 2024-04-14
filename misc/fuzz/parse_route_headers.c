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
	// Create a sip_msg_t struct and set its content based on the input Data and Size
	sip_msg_t msg;
	msg.len = Size;
	msg.buf = malloc(Size + 1);

	// Check if allocation was successful
	if(msg.buf == NULL) {
		return 0;
	}

	// Copy the input Data into the msg.buf and null-terminate it
	memcpy(msg.buf, Data, Size);
	msg.buf[Size] = '\0';

	// Call the function to be fuzzed with the prepared sip_msg_t struct
	int result = parse_route_headers(&msg);

	// Free the allocated memory
	free(msg.buf);

	// Return the result, although it's not necessary in most fuzzing frameworks
	return 0;
}