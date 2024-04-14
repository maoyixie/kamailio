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
	struct sip_msg msg;
	hdr_flags_t flags;
	int next;

	// Initialize the structure with zeros
	memset(&msg, 0, sizeof(struct sip_msg));

	// Initialize flags and next with random values
	flags = (hdr_flags_t)(Data[0] | Data[1] << 8 | Data[2] << 16
						  | Data[3] << 24);
	next = (int)(Data[4] | Data[5] << 8 | Data[6] << 16 | Data[7] << 24);

	// Ensure the input data is null-terminated and does not exceed the buffer size
	if(Size < sizeof(msg.buf) - 1) {
		memcpy(msg.buf, Data + 8, Size - 8);
		msg.buf[Size - 8] = '\0';
	} else {
		memcpy(msg.buf, Data + 8, sizeof(msg.buf) - 1);
		msg.buf[sizeof(msg.buf) - 1] = '\0';
	}

	// Call the target function to be fuzzed
	parse_headers(&msg, flags, next);

	// Indicate success
	return 0;
}