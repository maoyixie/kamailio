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
	// Create a sip_msg structure
	struct sip_msg msg;

	// Copy the input data into the sip_msg structure
	msg.buf = malloc(Size + 1);
	if(!msg.buf) {
		return 0;
	}
	memcpy(msg.buf, Data, Size);
	msg.buf[Size] = '\0';
	msg.len = Size;

	// Fuzz the parse_diversion_header function
	parse_diversion_header(&msg);

	// Clean up the allocated memory
	free(msg.buf);

	return 0;
}