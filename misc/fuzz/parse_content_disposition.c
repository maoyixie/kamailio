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
	// Ensure the input data is null-terminated and fits into the buffer
	const size_t BufSize = 256;
	char buffer[BufSize];

	if(Size > BufSize - 1) {
		Size = BufSize - 1;
	}
	memcpy(buffer, Data, Size);
	buffer[Size] = '\0';

	// Create a sip_msg struct and set the content_disposition field to the fuzzed input
	struct sip_msg msg;
	msg.content_disposition = buffer;

	// Call the function to be fuzzed with the created sip_msg struct
	parse_content_disposition(&msg);

	return 0;
}