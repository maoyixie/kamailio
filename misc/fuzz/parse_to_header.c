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
	// Create a struct sip_msg to hold the input data
	struct sip_msg msg;

	// Check if the input data is non-empty and null-terminate it
	if(Size > 0) {
		uint8_t *null_terminated_data = (uint8_t *)malloc(Size + 1);
		if(!null_terminated_data) {
			return 0; // Return early if memory allocation failed
		}

		memcpy(null_terminated_data, Data, Size);
		null_terminated_data[Size] = '\0';

		// Set msg.buf to the null-terminated input data
		msg.buf = (char *)null_terminated_data;
		msg.len = Size;

		// Fuzz the parse_to_header function
		parse_to_header(&msg);

		// Free allocated memory
		free(null_terminated_data);
	}

	return 0;
}