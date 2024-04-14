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
	sip_uri_t *uri;

	// Ensure the input data is null-terminated
	uint8_t *DataCopy = (uint8_t *)malloc(Size + 1);
	if(!DataCopy) {
		return 0;
	}
	memcpy(DataCopy, Data, Size);
	DataCopy[Size] = '\0';

	// Initialize the sip_msg structure with the input data
	msg.buf = (char *)DataCopy;
	msg.len = Size;

	// Call the target function with the prepared input
	uri = parse_to_uri(&msg);

	// Clean up
	if(uri) {
		free(uri);
	}
	free(DataCopy);

	// Indicate that the fuzz test was successful
	return 0;
}