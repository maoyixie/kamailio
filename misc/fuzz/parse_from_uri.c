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
	sip_msg_t msg;
	char *data_copy;

	// Ensure we have a non-empty input
	if(Size == 0 || Data == NULL) {
		return 0;
	}

	// Allocate and copy the data
	data_copy = (char *)malloc(Size + 1);
	if(data_copy == NULL) {
		return 0;
	}

	memcpy(data_copy, Data, Size);
	data_copy[Size] = '\0'; // Null-terminate the string

	// Initialize the sip_msg_t structure
	msg.buf = data_copy;
	msg.len = Size;

	// Call the function to fuzz
	sip_uri_t *uri = parse_from_uri(&msg);

	// Cleanup
	if(uri != NULL) {
		free(uri);
	}
	free(data_copy);

	return 0;
}