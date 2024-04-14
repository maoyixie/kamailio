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
	// Allocate memory for the sip_msg structure
	struct sip_msg *msg = (struct sip_msg *)malloc(sizeof(struct sip_msg));
	if(!msg) {
		return 0;
	}

	// Initialize the sip_msg structure with the input data
	msg->buf = (char *)Data;
	msg->len = Size;

	// Call the target function with the fuzzed input
	int result = parse_pai_header(msg);

	// Free the allocated memory
	free(msg);

	// Return the result
	return 0;
}