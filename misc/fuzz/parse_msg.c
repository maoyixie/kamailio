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
	int ret;

	// Ensure there is enough space for null terminator
	char *buf = (char *)malloc(Size + 1);
	if(!buf) {
		return 0; // Insufficient memory
	}

	// Copy input data to the buffer and null-terminate it
	memcpy(buf, Data, Size);
	buf[Size] = '\0';

	// Fuzz the parse_msg function
	ret = parse_msg(buf, (unsigned int)Size, &msg);

	// Free the allocated buffer
	free(buf);

	// Returning 0 indicates that the fuzzer should continue running
	return 0;
}